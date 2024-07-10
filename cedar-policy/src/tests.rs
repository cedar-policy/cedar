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

#![cfg(test)]
// PANIC SAFETY unit tests
#![allow(clippy::panic)]

use super::*;

use authorizer::Decision;
use cedar_policy_core::ast;
use cedar_policy_core::authorizer;
use cedar_policy_core::entities::{self};
use cedar_policy_core::test_utils::{expect_err, ExpectedErrorMessageBuilder};
use miette::Report;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

mod entity_uid_tests {
    use super::*;
    use cool_asserts::assert_matches;

    /// building an `EntityUid` from components
    #[test]
    fn entity_uid_from_parts() {
        let entity_id = EntityId::from_str("bobby").expect("failed at constructing EntityId");
        let entity_type_name = EntityTypeName::from_str("Chess::Master")
            .expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        assert_eq!(euid.id().as_ref(), "bobby");
        assert_eq!(euid.type_name().to_string(), "Chess::Master");
        assert_eq!(euid.type_name().basename(), "Master");
        assert_eq!(euid.type_name().namespace(), "Chess");
        assert_eq!(euid.type_name().namespace_components().count(), 1);
    }

    /// building an `EntityUid` from components, with no namespace
    #[test]
    fn entity_uid_no_namespace() {
        let entity_id = EntityId::from_str("bobby").expect("failed at constructing EntityId");
        let entity_type_name =
            EntityTypeName::from_str("User").expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        assert_eq!(euid.id().as_ref(), "bobby");
        assert_eq!(euid.type_name().to_string(), "User");
        assert_eq!(euid.type_name().basename(), "User");
        assert_eq!(euid.type_name().namespace(), String::new());
        assert_eq!(euid.type_name().namespace_components().count(), 0);
    }

    /// building an `EntityUid` from components, with many nested namespaces
    #[test]
    fn entity_uid_nested_namespaces() {
        let entity_id = EntityId::from_str("bobby").expect("failed at constructing EntityId");
        let entity_type_name = EntityTypeName::from_str("A::B::C::D::Z")
            .expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        assert_eq!(euid.id().as_ref(), "bobby");
        assert_eq!(euid.type_name().to_string(), "A::B::C::D::Z");
        assert_eq!(euid.type_name().basename(), "Z");
        assert_eq!(euid.type_name().namespace(), "A::B::C::D");
        assert_eq!(euid.type_name().namespace_components().count(), 4);
    }

    /// building an `EntityUid` from components, including escapes
    #[test]
    fn entity_uid_with_escape() {
        // EntityId contains some things that look like escapes
        let entity_id = EntityId::from_str(r"bobby\'s sister:\nVeronica")
            .expect("failed at constructing EntityId");
        let entity_type_name = EntityTypeName::from_str("Hockey::Master")
            .expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        // these are passed through (no escape interpretation):
        //   the EntityId has the literal backslash characters in it
        assert_eq!(euid.id().as_ref(), r"bobby\'s sister:\nVeronica");
        assert_eq!(euid.type_name().to_string(), "Hockey::Master");
        assert_eq!(euid.type_name().basename(), "Master");
        assert_eq!(euid.type_name().namespace(), "Hockey");
        assert_eq!(euid.type_name().namespace_components().count(), 1);
    }

    /// building an `EntityUid` from components, including backslashes
    #[test]
    fn entity_uid_with_backslashes() {
        // backslashes preceding a variety of characters
        let entity_id =
            EntityId::from_str(r#"\ \a \b \' \" \\"#).expect("failed at constructing EntityId");
        let entity_type_name =
            EntityTypeName::from_str("Test::User").expect("failed at constructing EntityTypeName");
        let euid = EntityUid::from_type_name_and_id(entity_type_name, entity_id);
        // the backslashes appear the same way in the EntityId
        assert_eq!(euid.id().as_ref(), r#"\ \a \b \' \" \\"#);
        assert_eq!(euid.type_name().to_string(), "Test::User");
    }

    /// building an `EntityUid` from components, including single and double quotes (and backslashes)
    #[test]
    fn entity_uid_with_quotes() {
        let euid: EntityUid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Test::User").unwrap(),
            EntityId::from_str(r#"b'ob"by\'s sis\"ter"#).unwrap(),
        );
        // EntityId is passed through (no escape interpretation):
        //   the EntityId has all the same literal characters in it
        assert_eq!(euid.id().as_ref(), r#"b'ob"by\'s sis\"ter"#);
        assert_eq!(euid.type_name().to_string(), r"Test::User");
    }

    /// building an `EntityUid` from components, including whitespace in various places
    #[test]
    fn entity_uid_with_whitespace() {
        EntityTypeName::from_str("A ::   B::C").expect_err("should fail due to RFC 9");
        EntityTypeName::from_str(" A :: B\n::C \n  ::D\n").expect_err("should fail due to RFC 9");

        // but embedded whitespace should be OK when parsing an actual policy
        let policy = Policy::from_str(
            r#"permit(principal == A ::   B::C :: " hi there are spaces ", action, resource);"#,
        )
        .expect("should succeed, see RFC 9");
        let PrincipalConstraint::Eq(euid) = policy.principal_constraint() else {
            panic!("expected `Eq` constraint");
        };
        assert_eq!(euid.id().as_ref(), " hi there are spaces ");
        assert_eq!(euid.type_name().to_string(), "A::B::C"); // expect to have been normalized
        assert_eq!(euid.type_name().basename(), "C");
        assert_eq!(euid.type_name().namespace(), "A::B");
        assert_eq!(euid.type_name().namespace_components().count(), 2);

        let policy = Policy::from_str(
            r#"
permit(principal ==  A :: B
    ::C
    :: D
    ::  " hi there are
    spaces and
    newlines ", action, resource);"#,
        )
        .expect("should succeed, see RFC 9");
        let PrincipalConstraint::Eq(euid) = policy.principal_constraint() else {
            panic!("expected `Eq` constraint")
        };
        assert_eq!(
            euid.id().as_ref(),
            " hi there are\n    spaces and\n    newlines "
        );
        assert_eq!(euid.type_name().to_string(), "A::B::C::D"); // expect to have been normalized
        assert_eq!(euid.type_name().basename(), "D");
        assert_eq!(euid.type_name().namespace(), "A::B::C");
        assert_eq!(euid.type_name().namespace_components().count(), 3);
    }

    #[test]
    fn malformed_entity_type_name_should_fail() {
        let src = "I'm an invalid name";
        let result = EntityTypeName::from_str(src);

        assert_matches!(result, Err(_));
        let error = result.unwrap_err();
        expect_err(
            src,
            &Report::new(error),
            &ExpectedErrorMessageBuilder::error("invalid token")
                .exactly_one_underline("")
                .build(),
        );
    }

    /// parsing an `EntityUid` from string
    #[test]
    fn parse_euid() {
        let parsed_eid: EntityUid = r#"Test::User::"bobby""#.parse().expect("Failed to parse");
        assert_eq!(parsed_eid.id().as_ref(), r"bobby");
        assert_eq!(parsed_eid.type_name().to_string(), r"Test::User");
    }

    /// parsing an `EntityUid` from string, including escapes
    #[test]
    fn parse_euid_with_escape() {
        // the EntityUid string has an escaped single-quote and escaped double-quote
        let parsed_eid: EntityUid = r#"Test::User::"b\'ob\"by""#.parse().expect("Failed to parse");
        // the escapes were interpreted:
        //   the EntityId has single-quote and double-quote characters (but no backslash characters)
        assert_eq!(parsed_eid.id().as_ref(), r#"b'ob"by"#);
        assert_eq!(parsed_eid.type_name().to_string(), r"Test::User");
    }

    /// parsing an `EntityUid` from string, including both escaped and unescaped single-quotes
    #[test]
    fn parse_euid_single_quotes() {
        // the EntityUid string has an unescaped and escaped single-quote
        let euid_str = r#"Test::User::"b'obby\'s sister""#;
        EntityUid::from_str(euid_str).expect_err("Should fail, not normalized -- see RFC 9");
        // but this should be accepted in an actual policy
        let policy_str = "permit(principal == ".to_string() + euid_str + ", action, resource);";
        let policy = Policy::from_str(&policy_str).expect("Should parse; see RFC 9");
        let PrincipalConstraint::Eq(parsed_euid) = policy.principal_constraint() else {
            panic!("Expected an Eq constraint");
        };
        // the escape was interpreted:
        //   the EntityId has both single-quote characters (but no backslash characters)
        assert_eq!(parsed_euid.id().as_ref(), r"b'obby's sister");
        assert_eq!(parsed_euid.type_name().to_string(), r"Test::User");
    }

    /// parsing an `EntityUid` from string, including whitespace
    #[test]
    fn parse_euid_whitespace() {
        let euid_str = " A ::B :: C:: D \n :: \n E\n :: \"hi\"";
        EntityUid::from_str(euid_str).expect_err("Should fail, not normalized -- see RFC 9");
        // but this should be accepted in an actual policy
        let policy_str = "permit(principal == ".to_string() + euid_str + ", action, resource);";
        let policy = Policy::from_str(&policy_str).expect("Should parse; see RFC 9");
        let PrincipalConstraint::Eq(parsed_euid) = policy.principal_constraint() else {
            panic!("Expected an Eq constraint");
        };
        assert_eq!(parsed_euid.id().as_ref(), "hi");
        assert_eq!(parsed_euid.type_name().to_string(), "A::B::C::D::E"); // expect to have been normalized
        assert_eq!(parsed_euid.type_name().basename(), "E");
        assert_eq!(parsed_euid.type_name().namespace(), "A::B::C::D");
        assert_eq!(parsed_euid.type_name().namespace_components().count(), 4);
    }

    /// test that we can parse the `Display` output of `EntityUid`
    #[test]
    fn euid_roundtrip() {
        let parsed_euid: EntityUid = r#"Test::User::"b\'ob""#.parse().expect("Failed to parse");
        assert_eq!(parsed_euid.id().as_ref(), r"b'ob");
        let reparsed: EntityUid = format!("{parsed_euid}")
            .parse()
            .expect("failed to roundtrip");
        assert_eq!(reparsed.id().as_ref(), r"b'ob");
    }
}

mod scope_constraints_tests {
    use super::*;

    #[test]
    fn principal_constraint_inline() {
        let p = Policy::from_str("permit(principal,action,resource);").unwrap();
        assert_eq!(p.principal_constraint(), PrincipalConstraint::Any);
        let euid = EntityUid::from_strs("T", "a");
        assert_eq!(euid.id().as_ref(), "a");
        assert_eq!(
            euid.type_name(),
            &EntityTypeName::from_str("T").expect("Failed to parse EntityTypeName")
        );
        let p =
            Policy::from_str("permit(principal == T::\"a\",action,resource == T::\"b\");").unwrap();
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::Eq(euid.clone())
        );
        let p = Policy::from_str("permit(principal in T::\"a\",action,resource);").unwrap();
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::In(euid.clone())
        );
        let p = Policy::from_str("permit(principal is T,action,resource);").unwrap();
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::Is(EntityTypeName::from_str("T").unwrap())
        );
        let p = Policy::from_str("permit(principal is T in T::\"a\",action,resource);").unwrap();
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::IsIn(EntityTypeName::from_str("T").unwrap(), euid)
        );
    }

    #[test]
    fn action_constraint_inline() {
        let p = Policy::from_str("permit(principal,action,resource);").unwrap();
        assert_eq!(p.action_constraint(), ActionConstraint::Any);
        let euid = EntityUid::from_strs("NN::N::Action", "a");
        assert_eq!(
            euid.type_name(),
            &EntityTypeName::from_str("NN::N::Action").expect("Failed to parse EntityTypeName")
        );
        let p = Policy::from_str(
            "permit(principal == T::\"b\",action == NN::N::Action::\"a\",resource == T::\"c\");",
        )
        .unwrap();
        assert_eq!(p.action_constraint(), ActionConstraint::Eq(euid.clone()));
        let p = Policy::from_str("permit(principal,action in [NN::N::Action::\"a\"],resource);")
            .unwrap();
        assert_eq!(p.action_constraint(), ActionConstraint::In(vec![euid]));
    }

    #[test]
    fn resource_constraint_inline() {
        let p = Policy::from_str("permit(principal,action,resource);").unwrap();
        assert_eq!(p.resource_constraint(), ResourceConstraint::Any);
        let euid = EntityUid::from_strs("NN::N::T", "a");
        assert_eq!(
            euid.type_name(),
            &EntityTypeName::from_str("NN::N::T").expect("Failed to parse EntityTypeName")
        );
        let p =
            Policy::from_str("permit(principal == T::\"b\",action,resource == NN::N::T::\"a\");")
                .unwrap();
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::Eq(euid.clone())
        );
        let p = Policy::from_str("permit(principal,action,resource in NN::N::T::\"a\");").unwrap();
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::In(euid.clone())
        );
        let p = Policy::from_str("permit(principal,action,resource is NN::N::T);").unwrap();
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::Is(EntityTypeName::from_str("NN::N::T").unwrap())
        );
        let p =
            Policy::from_str("permit(principal,action,resource is NN::N::T in NN::N::T::\"a\");")
                .unwrap();
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::IsIn(EntityTypeName::from_str("NN::N::T").unwrap(), euid)
        );
    }

    #[test]
    fn principal_constraint_link() {
        let p = link("permit(principal,action,resource);", HashMap::new());
        assert_eq!(p.principal_constraint(), PrincipalConstraint::Any);
        let euid = EntityUid::from_strs("T", "a");
        let p = link(
            "permit(principal == T::\"a\",action,resource);",
            HashMap::new(),
        );
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::Eq(euid.clone())
        );
        let p = link(
            "permit(principal in T::\"a\",action,resource);",
            HashMap::new(),
        );
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::In(euid.clone())
        );
        let map: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), euid.clone())).collect();
        let p = link(
            "permit(principal in ?principal,action,resource);",
            map.clone(),
        );
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::In(euid.clone())
        );
        let p = link(
            "permit(principal == ?principal,action,resource);",
            map.clone(),
        );
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::Eq(euid.clone())
        );

        let p = link(
            "permit(principal is T in T::\"a\",action,resource);",
            HashMap::new(),
        );
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::IsIn(EntityTypeName::from_str("T").unwrap(), euid.clone())
        );
        let p = link("permit(principal is T,action,resource);", HashMap::new());
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::Is(EntityTypeName::from_str("T").unwrap())
        );
        let p = link("permit(principal is T in ?principal,action,resource);", map);
        assert_eq!(
            p.principal_constraint(),
            PrincipalConstraint::IsIn(EntityTypeName::from_str("T").unwrap(), euid)
        );
    }

    #[test]
    fn action_constraint_link() {
        let p = link("permit(principal,action,resource);", HashMap::new());
        assert_eq!(p.action_constraint(), ActionConstraint::Any);
        let euid = EntityUid::from_strs("Action", "a");
        let p = link(
            "permit(principal,action == Action::\"a\",resource);",
            HashMap::new(),
        );
        assert_eq!(p.action_constraint(), ActionConstraint::Eq(euid.clone()));
        let p = link(
            "permit(principal,action in [Action::\"a\",Action::\"b\"],resource);",
            HashMap::new(),
        );
        assert_eq!(
            p.action_constraint(),
            ActionConstraint::In(vec![euid, EntityUid::from_strs("Action", "b"),])
        );
    }

    #[test]
    fn resource_constraint_link() {
        let p = link("permit(principal,action,resource);", HashMap::new());
        assert_eq!(p.resource_constraint(), ResourceConstraint::Any);
        let euid = EntityUid::from_strs("T", "a");
        let p = link(
            "permit(principal,action,resource == T::\"a\");",
            HashMap::new(),
        );
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::Eq(euid.clone())
        );
        let p = link(
            "permit(principal,action,resource in T::\"a\");",
            HashMap::new(),
        );
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::In(euid.clone())
        );
        let map: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::resource(), euid.clone())).collect();
        let p = link(
            "permit(principal,action,resource in ?resource);",
            map.clone(),
        );
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::In(euid.clone())
        );
        let p = link(
            "permit(principal,action,resource == ?resource);",
            map.clone(),
        );
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::Eq(euid.clone())
        );

        let p = link(
            "permit(principal,action,resource is T in T::\"a\");",
            HashMap::new(),
        );
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::IsIn(EntityTypeName::from_str("T").unwrap(), euid.clone())
        );
        let p = link("permit(principal,action,resource is T);", HashMap::new());
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::Is(EntityTypeName::from_str("T").unwrap())
        );
        let p = link("permit(principal,action,resource is T in ?resource);", map);
        assert_eq!(
            p.resource_constraint(),
            ResourceConstraint::IsIn(EntityTypeName::from_str("T").unwrap(), euid)
        );
    }

    fn link(src: &str, values: HashMap<SlotId, EntityUid>) -> Policy {
        let mut pset = PolicySet::new();
        let template = Template::parse(Some(PolicyId::new("Id")), src).unwrap();

        pset.add_template(template).unwrap();

        let link_id = PolicyId::new("link");
        pset.link(PolicyId::new("Id"), link_id.clone(), values)
            .unwrap();
        pset.policy(&link_id).unwrap().clone()
    }
}

/// Tests in this module are adapted from Core's `policy_set.rs` tests
mod policy_set_tests {
    use super::*;
    use cool_asserts::assert_matches;

    #[test]
    fn template_link_lookup() {
        let mut pset = PolicySet::new();
        let p = Policy::parse(
            Some(PolicyId::new("p")),
            "permit(principal,action,resource);",
        )
        .expect("Failed to parse");
        pset.add(p).expect("Failed to add");
        let template = Template::parse(
            Some(PolicyId::new("t")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template).expect("Add failed");

        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(PolicyId::new("t"), PolicyId::new("id"), env.clone())
            .expect("Failed to link");

        let p0 = pset.policy(&PolicyId::new("p")).unwrap();
        let tp = pset.policy(&PolicyId::new("id")).unwrap();

        assert_eq!(
            p0.template_links(),
            None,
            "A normal policy should not have template links"
        );
        assert_eq!(
            tp.template_links(),
            Some(env),
            "A template-linked policy's links should be stored properly"
        );
    }

    #[test]
    fn link_conflicts() {
        let mut pset = PolicySet::new();
        let p1 = Policy::parse(
            Some(PolicyId::new("id")),
            "permit(principal,action,resource);",
        )
        .expect("Failed to parse");
        pset.add(p1).expect("Failed to add");
        let template = Template::parse(
            Some(PolicyId::new("t")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template).expect("Add failed");

        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();

        let before_link = pset.clone();
        let r = pset.link(PolicyId::new("t"), PolicyId::new("id"), env);

        assert_matches!(
            r,
            Err(PolicySetError::Linking(policy_set_errors::LinkingError { inner: ast::LinkingError::PolicyIdConflict { id } })) =>{
                assert_eq!(id, ast::PolicyID::from_string("id"));
            }
        );
        assert_eq!(
            pset, before_link,
            "A failed link shouldn't mutate the policy set"
        );
    }

    #[test]
    fn policyset_add() {
        let mut pset = PolicySet::new();
        let static_policy = Policy::parse(
            Some(PolicyId::new("id")),
            "permit(principal,action,resource);",
        )
        .expect("Failed to parse");
        pset.add(static_policy).expect("Failed to add");

        let template = Template::parse(
            Some(PolicyId::new("t")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template).expect("Failed to add");

        let env1: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test1"))).collect();
        pset.link(PolicyId::new("t"), PolicyId::new("link"), env1)
            .expect("Failed to link");

        let env2: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test2"))).collect();

        let err = pset
            .link(PolicyId::new("t"), PolicyId::new("link"), env2.clone())
            .expect_err("Should have failed due to conflict with existing link id");
        match err {
            PolicySetError::Linking(_) => (),
            e => panic!("Wrong error: {e}"),
        }

        pset.link(PolicyId::new("t"), PolicyId::new("link2"), env2)
            .expect("Failed to link");

        let template2 = Template::parse(
            Some(PolicyId::new("t")),
            "forbid(principal, action, resource == ?resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template2)
            .expect_err("should have failed due to conflict on template id");
        let template2 = Template::parse(
            Some(PolicyId::new("t2")),
            "forbid(principal, action, resource == ?resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template2)
            .expect("Failed to add template");
        let env3: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::resource(), EntityUid::from_strs("Test", "test3"))).collect();

        pset.link(PolicyId::new("t"), PolicyId::new("unique3"), env3.clone())
            .expect_err("should have failed due to conflict on template id");

        pset.link(PolicyId::new("t2"), PolicyId::new("unique3"), env3)
            .expect("should succeed with unique ids");
    }

    #[test]
    fn policyset_remove() {
        let authorizer = Authorizer::new();
        let request = Request::new(
            EntityUid::from_strs("Test", "test"),
            EntityUid::from_strs("Action", "a"),
            EntityUid::from_strs("Resource", "b"),
            Context::empty(),
            None,
        )
        .unwrap();

        let e = r#"[
            {
                "uid": {"type":"Test","id":"test"},
                "attrs": {},
                "parents": []
            },
            {
                "uid": {"type":"Action","id":"a"},
                "attrs": {},
                "parents": []
            },
            {
                "uid": {"type":"Resource","id":"b"},
                "attrs": {},
                "parents": []
            }
        ]"#;
        let entities = Entities::from_json_str(e, None).expect("entity error");

        let mut pset = PolicySet::new();
        let static_policy = Policy::parse(
            Some(PolicyId::new("id")),
            "permit(principal,action,resource);",
        )
        .expect("Failed to parse");
        pset.add(static_policy).expect("Failed to add");

        //Allow
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Allow);

        pset.remove_static(PolicyId::new("id"))
            .expect("Failed to remove static policy");

        //Deny
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Deny);

        let template = Template::parse(
            Some(PolicyId::new("t")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template).expect("Failed to add");

        let linked_policy_id = PolicyId::new("linked");
        let env1: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(PolicyId::new("t"), linked_policy_id.clone(), env1)
            .expect("Failed to link");

        //Allow
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Allow);

        assert_matches!(
            pset.remove_static(PolicyId::new("t")),
            Err(PolicySetError::PolicyNonexistent(_))
        );

        let result = pset.unlink(linked_policy_id.clone());
        assert_matches!(result, Ok(_));

        assert_matches!(
            pset.remove_static(PolicyId::new("t")),
            Err(PolicySetError::PolicyNonexistent(_))
        );

        //Deny
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Deny);

        let env1: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(PolicyId::new("t"), linked_policy_id.clone(), env1)
            .expect("Failed to link");

        //Allow
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Allow);

        //Can't remove template that is still linked
        assert_matches!(
            pset.remove_template(PolicyId::new("t")),
            Err(PolicySetError::RemoveTemplateWithActiveLinks(_))
        );

        //Unlink first, then remove
        let result = pset.unlink(linked_policy_id);
        assert_matches!(result, Ok(_));
        pset.remove_template(PolicyId::new("t"))
            .expect("Failed to remove policy template");

        //Deny
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Deny);
    }

    #[test]
    fn pset_removal_prop_test_1() {
        let template = Template::parse(
            Some(PolicyId::new("policy0")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(PolicyId::new("policy0"), PolicyId::new("policy3"), env)
            .unwrap();
        let template = Template::parse(
            Some(PolicyId::new("policy3")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");

        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined(_))
        );
        assert_matches!(
            pset.remove_static(PolicyId::new("policy3")),
            Err(PolicySetError::PolicyNonexistent(_))
        );
        assert_matches!(
            pset.remove_template(PolicyId::new("policy3")),
            Err(PolicySetError::TemplateNonexistent(_))
        );
    }

    #[test]
    fn pset_requests() {
        let template = Template::parse(
            Some(PolicyId::new("template")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let static_policy = Policy::parse(
            Some(PolicyId::new("static")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        pset.add(static_policy).unwrap();
        pset.link(
            PolicyId::new("template"),
            PolicyId::new("linked"),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .expect("Link failure");

        assert_eq!(pset.templates().count(), 1);
        assert_eq!(pset.policies().count(), 2);
        assert_eq!(pset.policies().filter(|p| p.is_static()).count(), 1);

        assert_eq!(
            pset.template(&"template".parse().unwrap())
                .expect("lookup failed")
                .id(),
            &"template".parse().unwrap()
        );
        assert_eq!(
            pset.policy(&"static".parse().unwrap())
                .expect("lookup failed")
                .id(),
            &"static".parse().unwrap()
        );
        assert_eq!(
            pset.policy(&"linked".parse().unwrap())
                .expect("lookup failed")
                .id(),
            &"linked".parse().unwrap()
        );
    }

    #[test]
    fn link_static_policy() {
        // Linking the `PolicyId` of a static policy should not be allowed.
        // Attempting it should cause an `ExpectedTemplate` error.
        let static_policy = Policy::parse(
            Some(PolicyId::new("static")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        let mut pset = PolicySet::new();
        pset.add(static_policy).unwrap();

        let before_link = pset.clone();
        let result = pset.link(
            PolicyId::new("static"),
            PolicyId::new("linked"),
            HashMap::new(),
        );
        assert_matches!(result, Err(PolicySetError::ExpectedTemplate(_)));
        assert_eq!(
            pset, before_link,
            "A failed link shouldn't mutate the policy set"
        );
    }

    #[test]
    fn link_linked_policy() {
        let template = Template::parse(
            Some(PolicyId::new("template")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();

        pset.link(
            PolicyId::new("template"),
            PolicyId::new("linked"),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();

        let before_link = pset.clone();
        let result = pset.link(
            PolicyId::new("linked"),
            PolicyId::new("linked2"),
            HashMap::new(),
        );
        assert_matches!(result, Err(PolicySetError::ExpectedTemplate(_)));
        assert_eq!(
            pset, before_link,
            "A failed link shouldn't mutate the policy set"
        );
    }

    #[cfg(feature = "partial-eval")]
    #[test]
    fn unknown_entities() {
        let ast = ast::Policy::from_when_clause(
            ast::Effect::Permit,
            ast::Expr::unknown(ast::Unknown::new_with_type(
                "test_entity_type::\"unknown\"",
                ast::Type::Entity {
                    ty: "test_entity_type".parse().unwrap(),
                },
            )),
            ast::PolicyID::from_smolstr("static".into()),
            None,
        );
        let static_policy = Policy::from_ast(ast);
        let mut pset = PolicySet::new();
        pset.add(static_policy).unwrap();

        let entity_uids = pset.unknown_entities();
        entity_uids.contains(&"test_entity_type::\"unknown\"".parse().unwrap());
    }

    #[test]
    fn unlink_linked_policy() {
        let template = Template::parse(
            Some(PolicyId::new("template")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();

        let linked_policy_id = PolicyId::new("linked");
        pset.link(
            PolicyId::new("template"),
            linked_policy_id.clone(),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();

        let authorizer = Authorizer::new();
        let request = Request::new(
            EntityUid::from_strs("Test", "test"),
            EntityUid::from_strs("Action", "a"),
            EntityUid::from_strs("Resource", "b"),
            Context::empty(),
            None,
        )
        .unwrap();

        let e = r#"[
            {
                "uid": {"type":"Test","id":"test"},
                "attrs": {},
                "parents": []
            },
            {
                "uid": {"type":"Action","id":"a"},
                "attrs": {},
                "parents": []
            },
            {
                "uid": {"type":"Resource","id":"b"},
                "attrs": {},
                "parents": []
            }
        ]"#;
        let entities = Entities::from_json_str(e, None).expect("entity error");

        // Allow
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Allow);

        let result = pset.unlink(linked_policy_id.clone());
        assert_matches!(result, Ok(_));

        //Deny
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Deny);

        let result = pset.unlink(linked_policy_id);
        assert_matches!(result, Err(PolicySetError::LinkNonexistent(_)));
    }

    #[test]
    fn get_linked_policy() {
        let mut pset = PolicySet::new();

        let template = Template::parse(
            Some(PolicyId::new("template")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        pset.add_template(template).unwrap();

        let linked_policy_id = PolicyId::new("linked");
        pset.link(
            PolicyId::new("template"),
            linked_policy_id.clone(),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();

        //add link, count 1
        assert_eq!(
            pset.get_linked_policies(PolicyId::new("template"))
                .unwrap()
                .count(),
            1
        );
        let result = pset.unlink(linked_policy_id.clone());
        assert_matches!(result, Ok(_));
        //remove link, count 0
        assert_eq!(
            pset.get_linked_policies(PolicyId::new("template"))
                .unwrap()
                .count(),
            0
        );
        let result = pset.unlink(linked_policy_id.clone());
        assert_matches!(result, Err(PolicySetError::LinkNonexistent(_)));

        pset.link(
            PolicyId::new("template"),
            linked_policy_id.clone(),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();
        assert_eq!(
            pset.get_linked_policies(PolicyId::new("template"))
                .unwrap()
                .count(),
            1
        );
        pset.link(
            PolicyId::new("template"),
            PolicyId::new("linked2"),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();
        assert_eq!(
            pset.get_linked_policies(PolicyId::new("template"))
                .unwrap()
                .count(),
            2
        );

        //Can't re-add template
        let template = Template::parse(
            Some(PolicyId::new("template")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined(_))
        );

        //Add another template
        let template = Template::parse(
            Some(PolicyId::new("template2")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        pset.add_template(template).unwrap();

        //template2 count 0
        assert_eq!(
            pset.get_linked_policies(PolicyId::new("template2"))
                .unwrap()
                .count(),
            0
        );

        //template count 2
        assert_eq!(
            pset.get_linked_policies(PolicyId::new("template"))
                .unwrap()
                .count(),
            2
        );

        //Can't remove template
        assert_matches!(
            pset.remove_template(PolicyId::new("template")),
            Err(PolicySetError::RemoveTemplateWithActiveLinks(_))
        );

        //Can't add policy named template
        let illegal_template_policy = Policy::parse(
            Some(PolicyId::new("template")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        assert_matches!(
            pset.add(illegal_template_policy),
            Err(PolicySetError::AlreadyDefined(_))
        );

        //Can't add policy named linked
        let illegal_linked_policy = Policy::parse(
            Some(PolicyId::new("linked")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        assert_matches!(
            pset.add(illegal_linked_policy),
            Err(PolicySetError::AlreadyDefined(_))
        );

        //Can add policy named `policy`
        let static_policy = Policy::parse(
            Some(PolicyId::new("policy")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        pset.add(static_policy).unwrap();

        //Can remove `policy`
        pset.remove_static(PolicyId::new("policy"))
            .expect("should be able to remove policy");

        //Cannot remove "linked"
        assert_matches!(
            pset.remove_static(PolicyId::new("linked")),
            Err(PolicySetError::PolicyNonexistent(_))
        );

        //Cannot remove "template"
        assert_matches!(
            pset.remove_static(PolicyId::new("template")),
            Err(PolicySetError::PolicyNonexistent(_))
        );

        //template count 2
        assert_eq!(
            pset.get_linked_policies(PolicyId::new("template"))
                .unwrap()
                .count(),
            2
        );

        //unlink one policy, template count 1
        let result = pset.unlink(linked_policy_id);
        assert_matches!(result, Ok(_));
        assert_eq!(
            pset.get_linked_policies(PolicyId::new("template"))
                .unwrap()
                .count(),
            1
        );

        //remove template2
        assert_matches!(pset.remove_template(PolicyId::new("template2")), Ok(_));

        //can't remove template1
        assert_matches!(
            pset.remove_template(PolicyId::new("template")),
            Err(PolicySetError::RemoveTemplateWithActiveLinks(_))
        );

        //unlink other policy, template count 0
        let result = pset.unlink(PolicyId::new("linked2"));
        assert_matches!(result, Ok(_));
        assert_eq!(
            pset.get_linked_policies(PolicyId::new("template"))
                .unwrap()
                .count(),
            0
        );

        //remove template
        assert_matches!(pset.remove_template(PolicyId::new("template")), Ok(_));

        //can't get count for nonexistent template
        assert_matches!(
            pset.get_linked_policies(PolicyId::new("template"))
                .err()
                .unwrap(),
            PolicySetError::TemplateNonexistent(_)
        );
    }

    #[test]
    fn pset_add_conflict() {
        let template = Template::parse(
            Some(PolicyId::new("policy0")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(PolicyId::new("policy0"), PolicyId::new("policy1"), env)
            .unwrap();

        //fails for template; static
        let static_policy = Policy::parse(
            Some(PolicyId::new("policy0")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        assert_matches!(
            pset.add(static_policy),
            Err(PolicySetError::AlreadyDefined(_))
        );

        //fails for link; static
        let static_policy = Policy::parse(
            Some(PolicyId::new("policy1")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        assert_matches!(
            pset.add(static_policy),
            Err(PolicySetError::AlreadyDefined(_))
        );

        //fails for static; static
        let static_policy = Policy::parse(
            Some(PolicyId::new("policy2")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        pset.add(static_policy.clone()).unwrap();
        assert_matches!(
            pset.add(static_policy),
            Err(PolicySetError::AlreadyDefined(_))
        );
    }

    #[test]
    fn pset_add_template_conflict() {
        let template = Template::parse(
            Some(PolicyId::new("policy0")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(PolicyId::new("policy0"), PolicyId::new("policy3"), env)
            .unwrap();

        //fails for link; template
        let template = Template::parse(
            Some(PolicyId::new("policy3")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined(_))
        );

        //fails for template; template
        let template = Template::parse(
            Some(PolicyId::new("policy0")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined(_))
        );

        //fails for static; template
        let static_policy = Policy::parse(
            Some(PolicyId::new("policy1")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        pset.add(static_policy).unwrap();
        let template = Template::parse(
            Some(PolicyId::new("policy1")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined(_))
        );
    }

    #[test]
    fn pset_link_conflict() {
        let template = Template::parse(
            Some(PolicyId::new("policy0")),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();

        //fails for link; link
        pset.link(
            PolicyId::new("policy0"),
            PolicyId::new("policy3"),
            env.clone(),
        )
        .unwrap();
        assert_matches!(
            pset.link(
                PolicyId::new("policy0"),
                PolicyId::new("policy3"),
                env.clone(),
            ),
            Err(PolicySetError::Linking(policy_set_errors::LinkingError {
                inner: ast::LinkingError::PolicyIdConflict { .. }
            }))
        );

        //fails for template; link
        assert_matches!(
            pset.link(
                PolicyId::new("policy0"),
                PolicyId::new("policy0"),
                env.clone(),
            ),
            Err(PolicySetError::Linking(policy_set_errors::LinkingError {
                inner: ast::LinkingError::PolicyIdConflict { .. }
            }))
        );

        //fails for static; link
        let static_policy = Policy::parse(
            Some(PolicyId::new("policy1")),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        pset.add(static_policy).unwrap();
        assert_matches!(
            pset.link(PolicyId::new("policy0"), PolicyId::new("policy1"), env,),
            Err(PolicySetError::Linking(policy_set_errors::LinkingError {
                inner: ast::LinkingError::PolicyIdConflict { .. }
            }))
        );
    }
}

mod schema_tests {
    use super::*;
    use cool_asserts::assert_matches;
    use serde_json::json;

    /// A minimal test that a valid Schema parses
    #[test]
    fn valid_schema() {
        Schema::from_json_value(json!(
        { "": {
            "entityTypes": {
                "Photo": {
                    "memberOfTypes": [ "Album" ],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "foo": {
                                "type": "Boolean",
                                "required": false
                            }
                        }
                    }
                },
                "Album": {
                    "memberOfTypes": [ ],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "foo": {
                                "type": "Boolean",
                                "required": false
                            }
                        }
                    }
                }
            },
            "actions": {
                "view": {
                    "appliesTo": {
                        "principalTypes": ["Photo", "Album"],
                        "resourceTypes": ["Photo"]
                    }
                }
            }
        }}))
        .expect("schema should be valid");
    }

    /// Test that an invalid schema returns the appropriate error
    #[test]
    fn invalid_schema() {
        assert_matches!(
            Schema::from_json_str(
                // Written as a string because duplicate entity types are detected
                // by the serde-json string parser.
                r#"{"": {
                "entityTypes": {
                    "Photo": {
                        "memberOfTypes": [ "Album" ],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "Boolean",
                                    "required": false
                                }
                            }
                        }
                    },
                    "Album": {
                        "memberOfTypes": [ ],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "Boolean",
                                    "required": false
                                }
                            }
                        }
                    },
                    "Photo": {
                        "memberOfTypes": [ "Album" ],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "foo": {
                                    "type": "Boolean",
                                    "required": false
                                }
                            }
                        }
                    }
                },
                "actions": {
                    "view": {
                        "appliesTo": {
                            "principalTypes": ["Photo", "Album"],
                            "resourceTypes": ["Photo"]
                        }
                    }
                }
            }}"#
            ),
            Err(e) =>
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("failed to parse schema in JSON format: invalid entry: found duplicate key at line 39 column 17")
                        .build(),
                )
        );
    }
}

mod ancestors_tests {
    use super::*;

    #[test]
    fn test_ancestors() {
        let a_euid: EntityUid = EntityUid::from_strs("test", "A");
        let b_euid: EntityUid = EntityUid::from_strs("test", "b");
        let c_euid: EntityUid = EntityUid::from_strs("test", "C");
        let a = Entity::new_no_attrs(a_euid.clone(), HashSet::new());
        let b = Entity::new_no_attrs(b_euid.clone(), std::iter::once(a_euid.clone()).collect());
        let c = Entity::new_no_attrs(c_euid.clone(), std::iter::once(b_euid.clone()).collect());
        let es = Entities::from_entities([a, b, c], None).unwrap();
        let ans = es.ancestors(&c_euid).unwrap().collect::<HashSet<_>>();
        assert_eq!(ans.len(), 2);
        assert!(ans.contains(&b_euid));
        assert!(ans.contains(&a_euid));
    }
}

/// A few tests of validating entities.
/// Many other validation-related tests are in the separate module focusing on
/// schema-based parsing.
mod entity_validate_tests {
    use super::*;
    use entities::err::EntitiesError;
    use serde_json::json;

    fn schema() -> Schema {
        Schema::from_json_value(json!(
        {"": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "numDirectReports": { "type": "Long" },
                            "department": { "type": "String" },
                            "manager": { "type": "Entity", "name": "Employee" },
                            "hr_contacts": { "type": "Set", "element": {
                                "type": "Entity", "name": "HR" } },
                            "json_blob": { "type": "Record", "attributes": {
                                "inner1": { "type": "Boolean" },
                                "inner2": { "type": "String" },
                                "inner3": { "type": "Record", "attributes": {
                                    "innerinner": { "type": "Entity", "name": "Employee" }
                                }}
                            }},
                            "home_ip": { "type": "Extension", "name": "ipaddr" },
                            "work_ip": { "type": "Extension", "name": "ipaddr" },
                            "trust_score": { "type": "Extension", "name": "decimal" },
                            "tricky": { "type": "Record", "attributes": {
                                "type": { "type": "String" },
                                "id": { "type": "String" }
                            }}
                        }
                    }
                },
                "HR": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view": { }
            }
        }}
        ))
        .expect("should be a valid schema")
    }

    fn validate_entity(entity: Entity, schema: &Schema) -> Result<(), EntitiesError> {
        let _ = Entities::from_entities([entity], Some(schema))?;
        Ok(())
    }

    #[test]
    fn valid_entity() {
        let entity = Entity::new(
            EntityUid::from_strs("Employee", "123"),
            HashMap::from_iter([
                ("isFullTime".into(), RestrictedExpression::new_bool(false)),
                ("numDirectReports".into(), RestrictedExpression::new_long(3)),
                (
                    "department".into(),
                    RestrictedExpression::new_string("Sales".into()),
                ),
                (
                    "manager".into(),
                    RestrictedExpression::from_str(r#"Employee::"456""#).unwrap(),
                ),
                ("hr_contacts".into(), RestrictedExpression::new_set([])),
                (
                    "json_blob".into(),
                    RestrictedExpression::new_record([
                        ("inner1".into(), RestrictedExpression::new_bool(false)),
                        (
                            "inner2".into(),
                            RestrictedExpression::new_string("foo".into()),
                        ),
                        (
                            "inner3".into(),
                            RestrictedExpression::new_record([(
                                "innerinner".into(),
                                RestrictedExpression::from_str(r#"Employee::"abc""#).unwrap(),
                            )])
                            .unwrap(),
                        ),
                    ])
                    .unwrap(),
                ),
                (
                    "home_ip".into(),
                    RestrictedExpression::from_str(r#"ip("10.20.30.40")"#).unwrap(),
                ),
                (
                    "work_ip".into(),
                    RestrictedExpression::from_str(r#"ip("10.50.60.70")"#).unwrap(),
                ),
                (
                    "trust_score".into(),
                    RestrictedExpression::from_str(r#"decimal("36.53")"#).unwrap(),
                ),
                (
                    "tricky".into(),
                    RestrictedExpression::from_str(r#"{ type: "foo", id: "bar" }"#).unwrap(),
                ),
            ]),
            HashSet::new(),
        )
        .unwrap();
        validate_entity(entity.clone(), &schema()).unwrap();
        let (uid, attrs, parents) = entity.into_inner();
        validate_entity(Entity::new(uid, attrs, parents).unwrap(), &schema()).unwrap();
    }

    #[test]
    fn invalid_entities() {
        let schema = schema();
        let entity = Entity::new(
            EntityUid::from_strs("Employee", "123"),
            HashMap::from_iter([
                ("isFullTime".into(), RestrictedExpression::new_bool(false)),
                ("numDirectReports".into(), RestrictedExpression::new_long(3)),
                (
                    "department".into(),
                    RestrictedExpression::new_string("Sales".into()),
                ),
                (
                    "manager".into(),
                    RestrictedExpression::from_str(r#"Employee::"456""#).unwrap(),
                ),
                ("hr_contacts".into(), RestrictedExpression::new_set([])),
                (
                    "json_blob".into(),
                    RestrictedExpression::new_record([
                        ("inner1".into(), RestrictedExpression::new_bool(false)),
                        (
                            "inner2".into(),
                            RestrictedExpression::new_string("foo".into()),
                        ),
                        (
                            "inner3".into(),
                            RestrictedExpression::new_record([(
                                "innerinner".into(),
                                RestrictedExpression::from_str(r#"Employee::"abc""#).unwrap(),
                            )])
                            .unwrap(),
                        ),
                    ])
                    .unwrap(),
                ),
                (
                    "home_ip".into(),
                    RestrictedExpression::from_str(r#"ip("10.20.30.40")"#).unwrap(),
                ),
                (
                    "work_ip".into(),
                    RestrictedExpression::from_str(r#"ip("10.50.60.70")"#).unwrap(),
                ),
                (
                    "trust_score".into(),
                    RestrictedExpression::from_str(r#"decimal("36.53")"#).unwrap(),
                ),
                (
                    "tricky".into(),
                    RestrictedExpression::from_str(r#"{ type: "foo", id: "bar" }"#).unwrap(),
                ),
            ]),
            HashSet::from_iter([EntityUid::from_strs("Manager", "jane")]),
        )
        .unwrap();
        match validate_entity(entity, &schema) {
            Ok(()) => panic!("expected an error due to extraneous parent"),
            Err(e) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                        .source(r#"`Employee::"123"` is not allowed to have an ancestor of type `Manager` according to the schema"#)
                        .build()
                );
            }
        }

        let entity = Entity::new(
            EntityUid::from_strs("Employee", "123"),
            HashMap::from_iter([
                ("isFullTime".into(), RestrictedExpression::new_bool(false)),
                (
                    "department".into(),
                    RestrictedExpression::new_string("Sales".into()),
                ),
                (
                    "manager".into(),
                    RestrictedExpression::from_str(r#"Employee::"456""#).unwrap(),
                ),
                ("hr_contacts".into(), RestrictedExpression::new_set([])),
                (
                    "json_blob".into(),
                    RestrictedExpression::new_record([
                        ("inner1".into(), RestrictedExpression::new_bool(false)),
                        (
                            "inner2".into(),
                            RestrictedExpression::new_string("foo".into()),
                        ),
                        (
                            "inner3".into(),
                            RestrictedExpression::new_record([(
                                "innerinner".into(),
                                RestrictedExpression::from_str(r#"Employee::"abc""#).unwrap(),
                            )])
                            .unwrap(),
                        ),
                    ])
                    .unwrap(),
                ),
                (
                    "home_ip".into(),
                    RestrictedExpression::from_str(r#"ip("10.20.30.40")"#).unwrap(),
                ),
                (
                    "work_ip".into(),
                    RestrictedExpression::from_str(r#"ip("10.50.60.70")"#).unwrap(),
                ),
                (
                    "trust_score".into(),
                    RestrictedExpression::from_str(r#"decimal("36.53")"#).unwrap(),
                ),
                (
                    "tricky".into(),
                    RestrictedExpression::from_str(r#"{ type: "foo", id: "bar" }"#).unwrap(),
                ),
            ]),
            HashSet::new(),
        )
        .unwrap();
        match validate_entity(entity, &schema) {
            Ok(()) => panic!("expected an error due to missing attribute `numDirectReports`"),
            Err(e) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                        .source(r#"expected entity `Employee::"123"` to have attribute `numDirectReports`, but it does not"#)
                        .build()
                );
            }
        }

        let entity = Entity::new(
            EntityUid::from_strs("Employee", "123"),
            HashMap::from_iter([
                ("isFullTime".into(), RestrictedExpression::new_bool(false)),
                ("extra".into(), RestrictedExpression::new_bool(true)),
                ("numDirectReports".into(), RestrictedExpression::new_long(3)),
                (
                    "department".into(),
                    RestrictedExpression::new_string("Sales".into()),
                ),
                (
                    "manager".into(),
                    RestrictedExpression::from_str(r#"Employee::"456""#).unwrap(),
                ),
                ("hr_contacts".into(), RestrictedExpression::new_set([])),
                (
                    "json_blob".into(),
                    RestrictedExpression::new_record([
                        ("inner1".into(), RestrictedExpression::new_bool(false)),
                        (
                            "inner2".into(),
                            RestrictedExpression::new_string("foo".into()),
                        ),
                        (
                            "inner3".into(),
                            RestrictedExpression::new_record([(
                                "innerinner".into(),
                                RestrictedExpression::from_str(r#"Employee::"abc""#).unwrap(),
                            )])
                            .unwrap(),
                        ),
                    ])
                    .unwrap(),
                ),
                (
                    "home_ip".into(),
                    RestrictedExpression::from_str(r#"ip("10.20.30.40")"#).unwrap(),
                ),
                (
                    "work_ip".into(),
                    RestrictedExpression::from_str(r#"ip("10.50.60.70")"#).unwrap(),
                ),
                (
                    "trust_score".into(),
                    RestrictedExpression::from_str(r#"decimal("36.53")"#).unwrap(),
                ),
                (
                    "tricky".into(),
                    RestrictedExpression::from_str(r#"{ type: "foo", id: "bar" }"#).unwrap(),
                ),
            ]),
            HashSet::new(),
        )
        .unwrap();
        match validate_entity(entity, &schema) {
            Ok(()) => panic!("expected an error due to extraneous attribute"),
            Err(e) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                        .source(r#"attribute `extra` on `Employee::"123"` should not exist according to the schema"#)
                        .build()
                );
            }
        }

        let entity = Entity::new_no_attrs(EntityUid::from_strs("Manager", "jane"), HashSet::new());
        match validate_entity(entity, &schema) {
            Ok(()) => panic!("expected an error due to unexpected entity type"),
            Err(e) => {
                expect_err(
                    "",
                    &Report::new(e),
                    &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                        .source(r#"entity `Manager::"jane"` has type `Manager` which is not declared in the schema"#)
                        .build()
                );
            }
        }
    }
}

/// The main unit tests for schema-based parsing live here, as they require both
/// the Validator and Core packages working together.
///
/// (Core has similar tests, but using a stubbed implementation of Schema.)
mod schema_based_parsing_tests {
    use super::*;
    use cedar_policy_core::extensions::Extensions;
    use entities::conformance::err::EntitySchemaConformanceError;
    use entities::err::EntitiesError;

    use cool_asserts::assert_matches;
    use serde_json::json;

    #[test]
    fn entity_parse1() {
        let e = r#"{
            "uid" : { "type" : "User", "id" : "Alice" },
            "attrs" : {},
            "parents" : []
            }"#;
        let e = Entity::from_json_str(e, None).unwrap();
        let (uid, attrs, parents) = e.into_inner();
        let expected = r#"User::"Alice""#.parse().unwrap();
        assert_eq!(uid, expected);
        assert!(attrs.is_empty());
        assert!(parents.is_empty());
    }

    /// Simple test that exercises a variety of attribute types for single entities
    #[test]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::cognitive_complexity)]
    fn signle_attr_types() {
        let schema = Schema::from_json_value(json!(
        {"": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "numDirectReports": { "type": "Long" },
                            "department": { "type": "String" },
                            "manager": { "type": "Entity", "name": "Employee" },
                            "hr_contacts": { "type": "Set", "element": {
                                "type": "Entity", "name": "HR" } },
                            "json_blob": { "type": "Record", "attributes": {
                                "inner1": { "type": "Boolean" },
                                "inner2": { "type": "String" },
                                "inner3": { "type": "Record", "attributes": {
                                    "innerinner": { "type": "Entity", "name": "Employee" }
                                }}
                            }},
                            "home_ip": { "type": "Extension", "name": "ipaddr" },
                            "work_ip": { "type": "Extension", "name": "ipaddr" },
                            "trust_score": { "type": "Extension", "name": "decimal" },
                            "tricky": { "type": "Record", "attributes": {
                                "type": { "type": "String" },
                                "id": { "type": "String" }
                            }}
                        }
                    }
                },
                "HR": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view": { }
            }
        }}
        ))
        .expect("should be a valid schema");

        let entity = json!(
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
        );
        // without schema-based parsing, `home_ip` and `trust_score` are
        // strings, `manager` and `work_ip` are Records, `hr_contacts` contains
        // Records, and `json_blob.inner3.innerinner` is a Record
        let parsed = Entity::from_json_value(entity.clone(), None).unwrap();
        assert_matches!(
            parsed.attr("home_ip"),
            Some(Ok(EvalResult::String(s))) if &s == "222.222.222.101"
        );
        assert_matches!(
            parsed.attr("trust_score"),
            Some(Ok(EvalResult::String(s))) if &s == "5.7"
        );
        assert_matches!(parsed.attr("manager"), Some(Ok(EvalResult::Record(_))));
        assert_matches!(parsed.attr("work_ip"), Some(Ok(EvalResult::Record(_))));
        {
            let Some(Ok(EvalResult::Set(set))) = parsed.attr("hr_contacts") else {
                panic!("expected hr_contacts attr to exist and be a Set")
            };
            let contact = set.iter().next().expect("should be at least one contact");
            assert_matches!(contact, EvalResult::Record(_));
        };
        {
            let Some(Ok(EvalResult::Record(rec))) = parsed.attr("json_blob") else {
                panic!("expected json_blob attr to exist and be a Record")
            };
            let inner3 = rec.get("inner3").expect("expected inner3 attr to exist");
            let EvalResult::Record(rec) = inner3 else {
                panic!("expected inner3 to be a Record")
            };
            let innerinner = rec
                .get("innerinner")
                .expect("expected innerinner attr to exist");
            assert_matches!(innerinner, EvalResult::Record(_));
        };
        // but with schema-based parsing, we get these other types
        let parsed =
            Entity::from_json_value(entity, Some(&schema)).expect("Should parse without error");
        assert_matches!(parsed.attr("isFullTime"), Some(Ok(EvalResult::Bool(true))));
        assert_matches!(
            parsed.attr("numDirectReports"),
            Some(Ok(EvalResult::Long(3)))
        );
        assert_matches!(
            parsed.attr("department"),
            Some(Ok(EvalResult::String(s))) if &s == "Sales"
        );
        assert_matches!(
            parsed.attr("manager"),
            Some(Ok(EvalResult::EntityUid(euid))) if euid == EntityUid::from_strs(
                "Employee", "34FB87"
            )
        );
        {
            let Some(Ok(EvalResult::Set(set))) = parsed.attr("hr_contacts") else {
                panic!("expected hr_contacts attr to exist and be a Set")
            };
            let contact = set.iter().next().expect("should be at least one contact");
            assert_matches!(contact, EvalResult::EntityUid(_));
        };
        {
            let Some(Ok(EvalResult::Record(rec))) = parsed.attr("json_blob") else {
                panic!("expected json_blob attr to exist and be a Record")
            };
            let inner3 = rec.get("inner3").expect("expected inner3 attr to exist");
            let EvalResult::Record(rec) = inner3 else {
                panic!("expected inner3 to be a Record")
            };
            let innerinner = rec
                .get("innerinner")
                .expect("expected innerinner attr to exist");
            assert_matches!(innerinner, EvalResult::EntityUid(_));
        };
        assert_matches!(
            parsed.attr("home_ip"),
            Some(Ok(EvalResult::ExtensionValue(ev))) if &ev == "222.222.222.101/32"
        );
        assert_matches!(
            parsed.attr("work_ip"),
            Some(Ok(EvalResult::ExtensionValue(ev))) if &ev == "2.2.2.0/24"
        );
        assert_matches!(
            parsed.attr("trust_score"),
            Some(Ok(EvalResult::ExtensionValue(ev))) if &ev == "5.7000"
        );

        // simple type mismatch with expected type
        let entity = json!(
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": "3",
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
        );
        let err = Entity::from_json_value(entity, Some(&schema))
            .expect_err("should fail due to type mismatch on numDirectReports");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                .source(r#"in attribute `numDirectReports` on `Employee::"12UA45"`, type mismatch: value was expected to have type long, but actually has type string: `"3"`"#)
                .build()
        );

        // another simple type mismatch with expected type
        let entity = json!(
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": "34FB87",
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
        );
        let err = Entity::from_json_value(entity, Some(&schema))
            .expect_err("should fail due to type mismatch on manager");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                .source(r#"in attribute `manager` on `Employee::"12UA45"`, expected a literal entity reference, but got `"34FB87"`"#)
                .help(r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#)
                .build()
        );

        // type mismatch where we expect a set and get just a single element
        let entity = json!(
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": { "type": "HR", "id": "aaaaa" },
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
        );
        let err = Entity::from_json_value(entity, Some(&schema))
            .expect_err("should fail due to type mismatch on hr_contacts");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                .source(r#"in attribute `hr_contacts` on `Employee::"12UA45"`, type mismatch: value was expected to have type (set of `HR`), but actually has type record with attributes: {"id" => (optional) string, "type" => (optional) string}: `{"id": "aaaaa", "type": "HR"}`"#)
                .build()
        );

        // type mismatch where we just get the wrong entity type
        let entity = json!(
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "HR", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
        );
        let err = Entity::from_json_value(entity, Some(&schema))
            .expect_err("should fail due to type mismatch on manager");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                .source(r#"in attribute `manager` on `Employee::"12UA45"`, type mismatch: value was expected to have type `Employee`, but actually has type `HR`: `HR::"34FB87"`"#)
                .build()
        );

        // type mismatch where we're expecting an extension type and get a
        // different extension type
        let entity = json!(
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": { "fn": "decimal", "arg": "3.33" },
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
        );
        let err = Entity::from_json_value(entity, Some(&schema))
            .expect_err("should fail due to type mismatch on home_ip");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                .source(r#"in attribute `home_ip` on `Employee::"12UA45"`, type mismatch: value was expected to have type ipaddr, but actually has type decimal: `decimal("3.33")`"#)
                .build()
        );

        // missing a record attribute entirely
        let entity = json!(
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
        );
        let err = Entity::from_json_value(entity, Some(&schema))
            .expect_err("should fail due to missing attribute \"inner2\"");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                .source(r#"in attribute `json_blob` on `Employee::"12UA45"`, expected the record to have an attribute `inner2`, but it does not"#)
                .build()
        );

        // record attribute has the wrong type
        let entity = json!(
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": 33,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
        );
        let err = Entity::from_json_value(entity, Some(&schema))
            .expect_err("should fail due to type mismatch on attribute \"inner1\"");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error_starts_with("entity does not conform to the schema")
                .source(r#"in attribute `json_blob` on `Employee::"12UA45"`, type mismatch: value was expected to have type record with attributes: "#)
                .build()
        );

        let entity = json!(
                {
                    "uid": { "__entity": { "type": "Employee", "id": "12UA45" } },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "__entity": { "type": "Employee", "id": "34FB87" } },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": { "__extn": { "fn": "ip", "arg": "222.222.222.101" } },
                        "work_ip": { "__extn": { "fn": "ip", "arg": "2.2.2.0/24" } },
                        "trust_score": { "__extn": { "fn": "decimal", "arg": "5.7" } },
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
        );

        Entity::from_json_value(entity, Some(&schema))
            .expect("this version with explicit __entity and __extn escapes should also pass");
    }

    /// Ensures that parsing multiple entities as a single entity fails
    #[test]
    fn entity_fails_multiple() {
        let json = json!(
        [
            {
                "uid" : { "type" : "User", "id" : "Alice" },
                "attrs" : {},
                "parents" : []
            },
            {
                "uid" : { "type" : "User", "id" : "Bob" },
                "attrs" : {},
                "parents" : []
            },
        ]);
        Entity::from_json_value(json, None).expect_err("Multiple entities should fail this parser");
        let json = json!(
        [
            {
                "uid" : { "type" : "User", "id" : "Alice" },
                "attrs" : {},
                "parents" : []
            }
        ]);
        Entity::from_json_value(json, None).expect_err("Multiple entities should fail this parser");
    }

    /// Simple test that exercises a variety of attribute types.
    #[test]
    #[allow(clippy::too_many_lines)]
    #[allow(clippy::cognitive_complexity)]
    fn attr_types() {
        let schema = Schema::from_json_value(json!(
        {"": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "numDirectReports": { "type": "Long" },
                            "department": { "type": "String" },
                            "manager": { "type": "Entity", "name": "Employee" },
                            "hr_contacts": { "type": "Set", "element": {
                                "type": "Entity", "name": "HR" } },
                            "json_blob": { "type": "Record", "attributes": {
                                "inner1": { "type": "Boolean" },
                                "inner2": { "type": "String" },
                                "inner3": { "type": "Record", "attributes": {
                                    "innerinner": { "type": "Entity", "name": "Employee" }
                                }}
                            }},
                            "home_ip": { "type": "Extension", "name": "ipaddr" },
                            "work_ip": { "type": "Extension", "name": "ipaddr" },
                            "trust_score": { "type": "Extension", "name": "decimal" },
                            "tricky": { "type": "Record", "attributes": {
                                "type": { "type": "String" },
                                "id": { "type": "String" }
                            }}
                        }
                    }
                },
                "HR": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view": { }
            }
        }}
        ))
        .expect("should be a valid schema");

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        // without schema-based parsing, `home_ip` and `trust_score` are
        // strings, `manager` and `work_ip` are Records, `hr_contacts` contains
        // Records, and `json_blob.inner3.innerinner` is a Record
        let parsed = Entities::from_json_value(entitiesjson.clone(), None)
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);
        let parsed = parsed
            .get(&EntityUid::from_strs("Employee", "12UA45"))
            .expect("that should be the employee id");
        assert_matches!(
            parsed.attr("home_ip"),
            Some(Ok(EvalResult::String(s))) if &s == "222.222.222.101"
        );
        assert_matches!(
            parsed.attr("trust_score"),
            Some(Ok(EvalResult::String(s))) if &s == "5.7"
        );
        assert_matches!(parsed.attr("manager"), Some(Ok(EvalResult::Record(_))));
        assert_matches!(parsed.attr("work_ip"), Some(Ok(EvalResult::Record(_))));
        {
            let Some(Ok(EvalResult::Set(set))) = parsed.attr("hr_contacts") else {
                panic!("expected hr_contacts attr to exist and be a Set")
            };
            let contact = set.iter().next().expect("should be at least one contact");
            assert_matches!(contact, EvalResult::Record(_));
        };
        {
            let Some(Ok(EvalResult::Record(rec))) = parsed.attr("json_blob") else {
                panic!("expected json_blob attr to exist and be a Record")
            };
            let inner3 = rec.get("inner3").expect("expected inner3 attr to exist");
            let EvalResult::Record(rec) = inner3 else {
                panic!("expected inner3 to be a Record")
            };
            let innerinner = rec
                .get("innerinner")
                .expect("expected innerinner attr to exist");
            assert_matches!(innerinner, EvalResult::Record(_));
        };
        // but with schema-based parsing, we get these other types
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 2); // Employee::"12UA45" and the one action
        assert_eq!(
            parsed
                .iter()
                .filter(|e| e.uid().type_name().basename() == "Action")
                .count(),
            1
        );
        let parsed = parsed
            .get(&EntityUid::from_strs("Employee", "12UA45"))
            .expect("that should be the employee id");
        assert_matches!(parsed.attr("isFullTime"), Some(Ok(EvalResult::Bool(true))));
        assert_matches!(
            parsed.attr("numDirectReports"),
            Some(Ok(EvalResult::Long(3)))
        );
        assert_matches!(
            parsed.attr("department"),
            Some(Ok(EvalResult::String(s))) if &s == "Sales"
        );
        assert_matches!(
            parsed.attr("manager"),
            Some(Ok(EvalResult::EntityUid(euid))) if euid == EntityUid::from_strs(
                "Employee", "34FB87"
            )
        );
        {
            let Some(Ok(EvalResult::Set(set))) = parsed.attr("hr_contacts") else {
                panic!("expected hr_contacts attr to exist and be a Set")
            };
            let contact = set.iter().next().expect("should be at least one contact");
            assert_matches!(contact, EvalResult::EntityUid(_));
        };
        {
            let Some(Ok(EvalResult::Record(rec))) = parsed.attr("json_blob") else {
                panic!("expected json_blob attr to exist and be a Record")
            };
            let inner3 = rec.get("inner3").expect("expected inner3 attr to exist");
            let EvalResult::Record(rec) = inner3 else {
                panic!("expected inner3 to be a Record")
            };
            let innerinner = rec
                .get("innerinner")
                .expect("expected innerinner attr to exist");
            assert_matches!(innerinner, EvalResult::EntityUid(_));
        };
        assert_matches!(
            parsed.attr("home_ip"),
            Some(Ok(EvalResult::ExtensionValue(ev))) if &ev == "222.222.222.101/32"
        );
        assert_matches!(
            parsed.attr("work_ip"),
            Some(Ok(EvalResult::ExtensionValue(ev))) if &ev == "2.2.2.0/24"
        );
        assert_matches!(
            parsed.attr("trust_score"),
            Some(Ok(EvalResult::ExtensionValue(ev))) if &ev == "5.7000"
        );

        // simple type mismatch with expected type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": "3",
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on numDirectReports");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                .source(r#"in attribute `numDirectReports` on `Employee::"12UA45"`, type mismatch: value was expected to have type long, but actually has type string: `"3"`"#)
                .build()
        );

        // another simple type mismatch with expected type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": "34FB87",
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on manager");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                .source(r#"in attribute `manager` on `Employee::"12UA45"`, expected a literal entity reference, but got `"34FB87"`"#)
                .help(r#"literal entity references can be made with `{ "type": "SomeType", "id": "SomeId" }`"#)
                .build()
        );

        // type mismatch where we expect a set and get just a single element
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": { "type": "HR", "id": "aaaaa" },
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on hr_contacts");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                .source(r#"in attribute `hr_contacts` on `Employee::"12UA45"`, type mismatch: value was expected to have type (set of `HR`), but actually has type record with attributes: {"id" => (optional) string, "type" => (optional) string}: `{"id": "aaaaa", "type": "HR"}`"#)
                .build()
        );

        // type mismatch where we just get the wrong entity type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "HR", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on manager");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                .source(r#"in attribute `manager` on `Employee::"12UA45"`, type mismatch: value was expected to have type `Employee`, but actually has type `HR`: `HR::"34FB87"`"#)
                .build()
        );

        // type mismatch where we're expecting an extension type and get a
        // different extension type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": { "fn": "decimal", "arg": "3.33" },
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on home_ip");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                .source(r#"in attribute `home_ip` on `Employee::"12UA45"`, type mismatch: value was expected to have type ipaddr, but actually has type decimal: `decimal("3.33")`"#)
                .build()
        );

        // missing a record attribute entirely
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to missing attribute \"inner2\"");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("error during entity deserialization")
                .source(r#"in attribute `json_blob` on `Employee::"12UA45"`, expected the record to have an attribute `inner2`, but it does not"#)
                .build()
        );

        // record attribute has the wrong type
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": 33,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": "222.222.222.101",
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": "5.7",
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to type mismatch on attribute \"inner1\"");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error_starts_with("entity does not conform to the schema")
                .source(r#"in attribute `json_blob` on `Employee::"12UA45"`, type mismatch: value was expected to have type record with attributes: "#)
                .build()
        );

        let entitiesjson = json!(
            [
                {
                    "uid": { "__entity": { "type": "Employee", "id": "12UA45" } },
                    "attrs": {
                        "isFullTime": true,
                        "numDirectReports": 3,
                        "department": "Sales",
                        "manager": { "__entity": { "type": "Employee", "id": "34FB87" } },
                        "hr_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "type": "HR", "id": "bbbbb" }
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": "-*/",
                            "inner3": { "innerinner": { "type": "Employee", "id": "09AE76" }},
                        },
                        "home_ip": { "__extn": { "fn": "ip", "arg": "222.222.222.101" } },
                        "work_ip": { "__extn": { "fn": "ip", "arg": "2.2.2.0/24" } },
                        "trust_score": { "__extn": { "fn": "decimal", "arg": "5.7" } },
                        "tricky": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );

        Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("this version with explicit __entity and __extn escapes should also pass");
    }

    /// Test that involves namespaced entity types
    #[test]
    fn namespaces() {
        let schema = Schema::from_str(
            r#"
        {"XYZCorp": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "department": { "type": "String" },
                            "manager": {
                                "type": "Entity",
                                "name": "XYZCorp::Employee"
                            }
                        }
                    }
                }
            },
            "actions": {
                "view": {}
            }
        }}
        "#,
        )
        .expect("should be a valid schema");

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "XYZCorp::Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "XYZCorp::Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 2); // XYZCorp::Employee::"12UA45" and one action
        assert_eq!(
            parsed
                .iter()
                .filter(|e| e.uid().type_name().basename() == "Action")
                .count(),
            1
        );
        let parsed = parsed
            .get(&EntityUid::from_strs("XYZCorp::Employee", "12UA45"))
            .expect("that should be the employee type and id");
        assert_matches!(parsed.attr("isFullTime"), Some(Ok(EvalResult::Bool(true))));
        assert_matches!(
            parsed.attr("department"),
            Some(Ok(EvalResult::String(s))) if &s == "Sales"
        );
        assert_matches!(
            parsed.attr("manager"),
            Some(Ok(EvalResult::EntityUid(euid))) if euid == EntityUid::from_strs(
                "XYZCorp::Employee",
                "34FB87"
            )
        );

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "XYZCorp::Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let err = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect_err("should fail due to manager being wrong entity type (missing namespace)");
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("entity does not conform to the schema")
                .source(r#"in attribute `manager` on `XYZCorp::Employee::"12UA45"`, type mismatch: value was expected to have type `XYZCorp::Employee`, but actually has type `Employee`: `Employee::"34FB87"`"#)
                .build()
        );
    }

    /// Test that involves optional attributes
    #[test]
    fn optional_attrs() {
        let schema = Schema::from_str(
            r#"
        {"": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "department": { "type": "String", "required": false },
                            "manager": { "type": "Entity", "name": "Employee" }
                        }
                    }
                }
            },
            "actions": {
                "view": {}
            }
        }}
        "#,
        )
        .expect("should be a valid schema");

        // all good here
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "department": "Sales",
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 2); // Employee::"12UA45" and one action
        assert_eq!(
            parsed
                .iter()
                .filter(|e| e.uid().type_name().basename() == "Action")
                .count(),
            1
        );

        // "department" shouldn't be required
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 2); // Employee::"12UA45" and the one action
        assert_eq!(
            parsed
                .iter()
                .filter(|e| e.uid().type_name().basename() == "Action")
                .count(),
            1
        );
    }

    #[test]
    fn schema_sanity_check() {
        let src = "{ , .. }";
        assert_matches!(
            Schema::from_str(src),
            Err(crate::SchemaError::JsonDeserialization(_))
        );
    }

    #[test]
    fn template_constraint_sanity_checks() {
        assert!(!TemplatePrincipalConstraint::Any.has_slot());
        assert!(!TemplatePrincipalConstraint::In(Some(EntityUid::from_strs("a", "a"))).has_slot());
        assert!(!TemplatePrincipalConstraint::Eq(Some(EntityUid::from_strs("a", "a"))).has_slot());
        assert!(TemplatePrincipalConstraint::In(None).has_slot());
        assert!(TemplatePrincipalConstraint::Eq(None).has_slot());
        assert!(!TemplateResourceConstraint::Any.has_slot());
        assert!(!TemplateResourceConstraint::In(Some(EntityUid::from_strs("a", "a"))).has_slot());
        assert!(!TemplateResourceConstraint::Eq(Some(EntityUid::from_strs("a", "a"))).has_slot());
        assert!(TemplateResourceConstraint::In(None).has_slot());
        assert!(TemplateResourceConstraint::Eq(None).has_slot());
    }

    #[test]
    fn template_principal_constraints() {
        let src = r"
            permit(principal, action, resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(t.principal_constraint(), TemplatePrincipalConstraint::Any);

        let src = r"
            permit(principal == ?principal, action, resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::Eq(None)
        );

        let src = r#"
            permit(principal == A::"a", action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::Eq(Some(EntityUid::from_strs("A", "a")))
        );

        let src = r"
            permit(principal in ?principal, action, resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::In(None)
        );

        let src = r#"
            permit(principal in A::"a", action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::In(Some(EntityUid::from_strs("A", "a")))
        );

        let src = r"
            permit(principal is A, action, resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::Is(EntityTypeName::from_str("A").unwrap())
        );
        let src = r"
            permit(principal is A in ?principal, action, resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::IsIn(EntityTypeName::from_str("A").unwrap(), None)
        );
        let src = r#"
            permit(principal is A in A::"a", action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::IsIn(
                EntityTypeName::from_str("A").unwrap(),
                Some(EntityUid::from_strs("A", "a"))
            )
        );
    }

    #[test]
    fn template_action_constraints() {
        let src = r"
            permit(principal, action, resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(t.action_constraint(), ActionConstraint::Any);

        let src = r#"
            permit(principal, action == Action::"A", resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.action_constraint(),
            ActionConstraint::Eq(EntityUid::from_strs("Action", "A"))
        );

        let src = r#"
            permit(principal, action in [Action::"A", Action::"B"], resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.action_constraint(),
            ActionConstraint::In(vec![
                EntityUid::from_strs("Action", "A"),
                EntityUid::from_strs("Action", "B")
            ])
        );
    }

    #[test]
    fn template_resource_constraints() {
        let src = r"
            permit(principal, action, resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(t.resource_constraint(), TemplateResourceConstraint::Any);

        let src = r"
            permit(principal, action, resource == ?resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::Eq(None)
        );

        let src = r#"
            permit(principal, action, resource == A::"a");
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::Eq(Some(EntityUid::from_strs("A", "a")))
        );

        let src = r"
            permit(principal, action, resource in ?resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::In(None)
        );

        let src = r#"
            permit(principal, action, resource in A::"a");
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::In(Some(EntityUid::from_strs("A", "a")))
        );

        let src = r"
            permit(principal, action, resource is A);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::Is(EntityTypeName::from_str("A").unwrap())
        );
        let src = r"
            permit(principal, action, resource is A in ?resource);
        ";
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::IsIn(EntityTypeName::from_str("A").unwrap(), None)
        );
        let src = r#"
            permit(principal, action, resource is A in A::"a");
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::IsIn(
                EntityTypeName::from_str("A").unwrap(),
                Some(EntityUid::from_strs("A", "a"))
            )
        );
    }

    #[test]
    fn schema_namespace() {
        let fragment: SchemaFragment = r#"
        {
            "Foo::Bar": {
                "entityTypes": {},
                "actions": {}
            }
        }
        "#
        .parse()
        .unwrap();
        let namespaces = fragment.namespaces().next().unwrap();
        assert_eq!(
            namespaces.map(|ns| ns.to_string()),
            Some("Foo::Bar".to_string())
        );
        let _schema: Schema = fragment.try_into().expect("Should convert to schema");

        let fragment: SchemaFragment = r#"
        {
            "": {
                "entityTypes": {},
                "actions": {}
            }
        }
        "#
        .parse()
        .unwrap();
        let namespaces = fragment.namespaces().next().unwrap();
        assert_eq!(namespaces, None);
        let _schema: Schema = fragment.try_into().expect("Should convert to schema");
    }

    #[test]
    fn load_multiple_namespaces() {
        let fragment = SchemaFragment::from_json_value(json!({
            "Foo::Bar": {
                "entityTypes": {
                    "Baz": {
                        "memberOfTypes": ["Bar::Foo::Baz"]
                    }
                },
                "actions": {}
            },
            "Bar::Foo": {
                "entityTypes": {
                    "Baz": {
                        "memberOfTypes": ["Foo::Bar::Baz"]
                    }
                },
                "actions": {}
            }
        }))
        .unwrap();

        let schema = Schema::from_schema_fragments([fragment]).unwrap();

        assert!(schema
            .0
            .get_entity_type(&"Foo::Bar::Baz".parse().unwrap())
            .is_some());
        assert!(schema
            .0
            .get_entity_type(&"Bar::Foo::Baz".parse().unwrap())
            .is_some());
    }

    #[test]
    fn get_attributes_from_schema() {
        let fragment: SchemaFragment = SchemaFragment::from_json_value(json!({
        "": {
            "entityTypes": {},
            "actions": {
                "A": {},
                "B": {
                    "memberOf": [{"id": "A"}]
                },
                "C": {
                    "memberOf": [{"id": "A"}]
                },
                "D": {
                    "memberOf": [{"id": "B"}, {"id": "C"}]
                },
                "E": {
                    "memberOf": [{"id": "D"}]
                }
            }
        }}))
        .unwrap();

        let schema = Schema::from_schema_fragments([fragment]).unwrap();
        let action_entities = schema.action_entities().unwrap();

        let a_euid = EntityUid::from_strs("Action", "A");
        let b_euid = EntityUid::from_strs("Action", "B");
        let c_euid = EntityUid::from_strs("Action", "C");
        let d_euid = EntityUid::from_strs("Action", "D");
        let e_euid = EntityUid::from_strs("Action", "E");

        assert_eq!(
            action_entities,
            Entities::from_entities(
                [
                    Entity::new_no_attrs(a_euid.clone(), HashSet::new()),
                    Entity::new_no_attrs(b_euid.clone(), HashSet::from([a_euid.clone()])),
                    Entity::new_no_attrs(c_euid.clone(), HashSet::from([a_euid.clone()])),
                    Entity::new_no_attrs(
                        d_euid.clone(),
                        HashSet::from([a_euid.clone(), b_euid.clone(), c_euid.clone()])
                    ),
                    Entity::new_no_attrs(e_euid, HashSet::from([a_euid, b_euid, c_euid, d_euid])),
                ],
                Some(&schema)
            )
            .unwrap()
        );
    }

    #[test]
    fn entities_duplicates_fail() {
        let json = serde_json::json!([
            {
                "uid" : {
                    "type" : "User",
                    "id" : "alice"
                },
                "attrs" : {},
                "parents": []
            },
            {
                "uid" : {
                    "type" : "User",
                    "id" : "alice"
                },
                "attrs" : {},
                "parents": []
            }
        ]);
        let r = Entities::from_json_value(json.clone(), None).unwrap_err();
        match r {
            EntitiesError::Duplicate(euid) => {
                expect_err(
                    &json,
                    &Report::new(euid),
                    &ExpectedErrorMessageBuilder::error(
                        r#"duplicate entity entry `User::"alice"`"#,
                    )
                    .build(),
                );
            }
            e => panic!("Wrong error. Expected `Duplicate`, got: {e:?}"),
        }
    }

    /// Test that schema-based parsing accepts unknowns in any position where any type is expected
    #[test]
    fn issue_418() {
        let json = json!(
        {"": {
            "entityTypes": {
                "Employee": {
                    "memberOfTypes": [],
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "isFullTime": { "type": "Boolean" },
                            "numDirectReports": { "type": "Long" },
                            "department": { "type": "String" },
                            "manager": { "type": "Entity", "name": "Employee" },
                            "hr_contacts": { "type": "Set", "element": {
                                "type": "Entity", "name": "HR" } },
                            "sales_contacts": { "type": "Set", "element": {
                                "type": "Entity", "name": "Employee" } },
                            "json_blob": { "type": "Record", "attributes": {
                                "inner1": { "type": "Boolean" },
                                "inner2": { "type": "String" },
                                "inner3": { "type": "Record", "attributes": {
                                    "innerinner": { "type": "Entity", "name": "Employee" }
                                }}
                            }},
                            "home_ip": { "type": "Extension", "name": "ipaddr" },
                            "work_ip": { "type": "Extension", "name": "ipaddr" },
                            "trust_score": { "type": "Extension", "name": "decimal" },
                            "tricky": { "type": "Record", "attributes": {
                                "type": { "type": "String" },
                                "id": { "type": "String" }
                            }}
                        }
                    }
                },
                "HR": {
                    "memberOfTypes": []
                }
            },
            "actions": {
                "view": { }
            }
        }}
        );
        let schema = Schema::from_json_value(json).expect("should be a valid schema");

        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": { "__extn": { "fn": "unknown", "arg": "abc" }},
                        "numDirectReports": { "__extn": { "fn": "unknown", "arg": "def" }},
                        "department": { "__extn": { "fn": "unknown", "arg": "zxy" }},
                        "manager": { "__extn": { "fn": "unknown", "arg": "www" }},
                        "hr_contacts": { "__extn": { "fn": "unknown", "arg": "yyy" }},
                        "sales_contacts": [
                            { "type": "HR", "id": "aaaaa" },
                            { "__extn": { "fn": "unknown", "arg": "123" }}
                        ],
                        "json_blob": {
                            "inner1": false,
                            "inner2": { "__extn": { "fn": "unknown", "arg": "hhh" }},
                            "inner3": { "innerinner": { "__extn": { "fn": "unknown", "arg": "bbb" }}},
                        },
                        "home_ip": { "__extn": { "fn": "unknown", "arg": "uuu" }},
                        "work_ip": { "fn": "ip", "arg": "2.2.2.0/24" },
                        "trust_score": { "__extn": { "fn": "unknown", "arg": "dec" }},
                        "tricky": { "__extn": { "fn": "unknown", "arg": "ttt" }}
                    },
                    "parents": []
                }
            ]
        );

        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        let parsed = parsed
            .get(&EntityUid::from_strs("Employee", "12UA45"))
            .expect("that should be the employee id");
        let assert_contains_unknown = |err: &str, unk_name: &str| {
            assert!(
                err.contains("value contains a residual expression"),
                "actual error message was {err}"
            );
            assert!(err.contains(unk_name), "actual error message was {err}");
        };
        assert_matches!(
            parsed.attr("isFullTime"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "abc")
        );
        assert_matches!(
            parsed.attr("numDirectReports"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "def")
        );
        assert_matches!(
            parsed.attr("department"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "zxy")
        );
        assert_matches!(
            parsed.attr("manager"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "www")
        );
        assert_matches!(
            parsed.attr("hr_contacts"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "yyy")
        );
        assert_matches!(
            parsed.attr("sales_contacts"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "123")
        );
        assert_matches!(
            parsed.attr("json_blob"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "bbb")
        );
        assert_matches!(
            parsed.attr("home_ip"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "uuu")
        );
        assert_matches!(parsed.attr("work_ip"), Some(Ok(_)));
        assert_matches!(
            parsed.attr("trust_score"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "dec")
        );
        assert_matches!(
            parsed.attr("tricky"),
            Some(Err(e)) => assert_contains_unknown(&e.to_string(), "ttt")
        );
    }

    /// If a user passes actions through both the schema and the entities, then
    /// those actions should exactly match _unless_ the `TCComputation::ComputeNow`
    /// option is used, in which case only the TC has to match.
    #[test]
    fn issue_285() {
        let schema = Schema::from_json_value(json!(
        {"": {
            "entityTypes": {},
            "actions": {
                "A": {},
                "B": {
                    "memberOf": [{"id": "A"}]
                },
                "C": {
                    "memberOf": [{"id": "B"}]
                }
            }
        }}
        ))
        .expect("should be a valid schema");

        let entitiesjson_tc = json!(
            [
                {
                    "uid": { "type": "Action", "id": "A" },
                    "attrs": {},
                    "parents": []
                },
                {
                    "uid": { "type": "Action", "id": "B" },
                    "attrs": {},
                    "parents": [
                        { "type": "Action", "id": "A" }
                    ]
                },
                {
                    "uid": { "type": "Action", "id": "C" },
                    "attrs": {},
                    "parents": [
                        { "type": "Action", "id": "A" },
                        { "type": "Action", "id": "B" }
                    ]
                }
            ]
        );

        let entitiesjson_no_tc = json!(
            [
                {
                    "uid": { "type": "Action", "id": "A" },
                    "attrs": {},
                    "parents": []
                },
                {
                    "uid": { "type": "Action", "id": "B" },
                    "attrs": {},
                    "parents": [
                        { "type": "Action", "id": "A" }
                    ]
                },
                {
                    "uid": { "type": "Action", "id": "C" },
                    "attrs": {},
                    "parents": [
                        { "type": "Action", "id": "B" }
                    ]
                }
            ]
        );

        // Both entity jsons are ok (the default TC setting is `ComputeNow`)
        assert!(Entities::from_json_value(entitiesjson_tc, Some(&schema)).is_ok());
        assert!(Entities::from_json_value(entitiesjson_no_tc.clone(), Some(&schema)).is_ok());

        // Parsing will fail if the TC doesn't match
        let entitiesjson_bad = json!(
            [
                {
                    "uid": { "type": "Action", "id": "A" },
                    "attrs": {},
                    "parents": []
                },
                {
                    "uid": { "type": "Action", "id": "B" },
                    "attrs": {},
                    "parents": [
                        { "type": "Action", "id": "A" }
                    ]
                },
                {
                    "uid": { "type": "Action", "id": "C" },
                    "attrs": {},
                    "parents": [
                        { "type": "Action", "id": "A" }
                    ]
                }
            ]
        );
        assert!(matches!(
            Entities::from_json_value(entitiesjson_bad, Some(&schema)),
            Err(EntitiesError::InvalidEntity(
                EntitySchemaConformanceError::ActionDeclarationMismatch(_)
            ))
        ));

        // Parsing will fail if we change the TC setting
        let schema = cedar_policy_validator::CoreSchema::new(&schema.0);
        let parser_assume_computed = entities::EntityJsonParser::new(
            Some(&schema),
            Extensions::all_available(),
            entities::TCComputation::AssumeAlreadyComputed,
        );
        assert!(matches!(
            parser_assume_computed.from_json_value(entitiesjson_no_tc.clone()),
            Err(EntitiesError::InvalidEntity(
                EntitySchemaConformanceError::ActionDeclarationMismatch(_)
            ))
        ));

        let parser_enforce_computed = entities::EntityJsonParser::new(
            Some(&schema),
            Extensions::all_available(),
            entities::TCComputation::EnforceAlreadyComputed,
        );
        assert!(matches!(
            parser_enforce_computed.from_json_value(entitiesjson_no_tc),
            Err(EntitiesError::TransitiveClosureError(_))
        ));
    }
}

#[cfg(not(feature = "partial-validate"))]
#[test]
fn partial_schema_unsupported() {
    use cool_asserts::assert_matches;
    use serde_json::json;
    assert_matches!(
        Schema::from_json_value( json!({"": { "entityTypes": { "A": { "shape": { "type": "Record", "attributes": {}, "additionalAttributes": true } } }, "actions": {} }})),
        Err(e) =>
            expect_err(
                "",
                &Report::new(e),
                &ExpectedErrorMessageBuilder::error("unsupported feature used in schema")
                    .source("records and entities with `additionalAttributes` are experimental, but the experimental `partial-validate` feature is not enabled")
                    .build(),
            )
    );
}

#[cfg(feature = "partial-validate")]
mod partial_schema {
    use super::*;
    use serde_json::json;

    fn partial_schema() -> Schema {
        Schema::from_json_value(json!(
        {
            "": {
                "entityTypes": {
                    "User" : {},
                    "Folder" : {},
                    "Employee": {
                        "memberOfTypes": [],
                        "shape": {
                            "type": "Record",
                            "attributes": { },
                            "additionalAttributes": true,
                        },
                    }
                },
                "actions": {
                    "Act": {
                        "appliesTo": {
                            "principalTypes" : ["User"],
                            "resourceTypes" : ["Folder"],
                            "context": {
                                "type": "Record",
                                "attributes": {},
                                "additionalAttributes": true,
                            }
                        }
                    }
                }
            }
        }
        ))
        .unwrap()
    }

    #[test]
    fn entity_extra_attr() {
        let entitiesjson = json!(
            [
                {
                    "uid": { "type": "Employee", "id": "12UA45" },
                    "attrs": {
                        "isFullTime": true,
                        "foobar": 234,
                        "manager": { "type": "Employee", "id": "34FB87" }
                    },
                    "parents": []
                }
            ]
        );

        let schema = partial_schema();
        let parsed = Entities::from_json_value(entitiesjson.clone(), Some(&schema))
            .expect("Parsing with a partial schema should allow unknown attributes.");
        let parsed_without_schema = Entities::from_json_value(entitiesjson, None).unwrap();

        let uid = EntityUid::from_strs("Employee", "12UA45");
        assert_eq!(
            parsed.get(&uid),
            parsed_without_schema.get(&uid),
            "Parsing with a partial schema should give the same result as parsing without a schema"
        );
    }

    #[test]
    fn context_extra_attr() {
        Context::from_json_value(
            json!({"foo": true, "bar": 123}),
            Some((&partial_schema(), &EntityUid::from_strs("Action", "Act"))),
        )
        .unwrap();
    }
}

mod template_tests {
    use crate::Template;

    #[test]
    fn test_policy_template_to_json() {
        let template = Template::parse(
            None,
            "permit(principal == ?principal, action, resource in ?resource);",
        );
        assert_eq!(
            template.unwrap().to_json().unwrap().to_string(),
            r#"{"effect":"permit","principal":{"op":"==","slot":"?principal"},"action":{"op":"All"},"resource":{"op":"in","slot":"?resource"},"conditions":[]}"#
        );
    }

    #[test]
    fn test_policy_template_from_json() {
        let template = Template::from_json(None, serde_json::from_str(r#"{"effect":"permit","principal":{"op":"==","slot":"?principal"},"action":{"op":"All"},"resource":{"op":"in","slot":"?resource"},"conditions":[]}"#).unwrap());
        assert_eq!(
            template.unwrap().to_string(),
            "permit(principal == ?principal, action, resource in ?resource);".to_string()
        );
    }
}

mod issue_326 {
    #[test]
    fn shows_only_the_first_parse_error_in_display() {
        use crate::PolicySet;
        use cool_asserts::assert_matches;
        use itertools::Itertools;
        use miette::Diagnostic;
        use std::str::FromStr;

        let src = r"
            permit(principal action resource);
            permit(principal, action resource);
        ";
        assert_matches!(PolicySet::from_str(src), Err(e) => {
            assert!(e.to_string().contains("unexpected token `action`"), "actual error message was {e}");
            assert!(!e.to_string().contains("unexpected token `resource`"), "actual error message was {e}");
            // but the other error should show in related()
            assert!(
                e.related().into_iter().flatten().any(|err| err.to_string().contains("unexpected token `resource`")),
                "actual related error messages were\n{}",
                e.related().into_iter().flatten().map(ToString::to_string).join("\n")
            );
        });
    }
}

mod policy_id_tests {
    use super::*;
    #[test]
    fn test_default_policy_id() {
        let policy = crate::Policy::from_str(r"permit(principal, action, resource);")
            .expect("should succeed");
        let policy_id: &str = policy.id().as_ref();
        assert_eq!(policy_id, "policy0");
    }
}

mod error_source_tests {
    use super::*;
    use cool_asserts::assert_matches;
    use miette::Diagnostic;
    use serde_json::json;

    /// These errors should have both a source location (span) and attached source code.
    #[test]
    fn errors_have_source_location_and_source_code() {
        // parse errors
        let srcs = [
            r#"@one("two") @one("three") permit(principal, action, resource);"#,
            r#"superforbid ( principal in Group::"bad", action, resource );"#,
            r#"permit ( principal is User::"alice", action, resource );"#,
        ];
        for src in srcs {
            assert_matches!(PolicySet::from_str(src), Err(e) => {
                assert!(e.labels().is_some(), "no source span for the parse error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(e));
                assert!(e.source_code().is_some(), "no source code for the parse error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(e));
            });
        }

        // evaluation errors
        let srcs = [
            "1 + true",
            "3 has foo",
            "true && ([2, 3, 4] in [4, 5, 6])",
            "ip(3)",
        ];
        let euid: EntityUid = r#"Placeholder::"entity""#.parse().unwrap();
        let req = Request::new(euid.clone(), euid.clone(), euid, Context::empty(), None).unwrap();
        let entities = Entities::empty();
        for src in srcs {
            let expr = Expression::from_str(src).unwrap();
            assert_matches!(eval_expression(&req, &entities, &expr), Err(e) => {
                assert!(e.labels().is_some(), "no source span for the evaluation error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(e));
                assert!(e.source_code().is_some(), "no source code for the evaluation error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(e));
            });
        }

        // evaluation errors in policies
        let srcs = [
            "permit ( principal, action, resource ) when { 1 + true };",
            "permit ( principal, action, resource ) when { 3 has foo };",
            "permit ( principal, action, resource ) when { true && ([2, 3, 4] in [4, 5, 6]) };",
            "permit ( principal, action, resource ) when { ip(3) };",
        ];
        let euid: EntityUid = r#"Placeholder::"entity""#.parse().unwrap();
        let req = Request::new(euid.clone(), euid.clone(), euid, Context::empty(), None).unwrap();
        let entities = Entities::empty();
        for src in srcs {
            let pset = PolicySet::from_str(src).unwrap();
            let resp = Authorizer::new().is_authorized(&req, &pset, &entities);
            for _err in resp.diagnostics().errors() {
                /* TODO(#485): evaluation errors don't currently have source locations
                assert!(err.labels().is_some(), "no source span for the evaluation error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(err.clone()));
                assert!(err.source_code().is_some(), "no source code for the evaluation error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(err.clone()));
                */
            }
        }

        // validation errors
        let validator = Validator::new(
            Schema::from_json_value(json!({ "": { "actions": { "view": {} }, "entityTypes": {} }}))
                .unwrap(),
        );
        // same srcs as above
        for src in srcs {
            let pset = PolicySet::from_str(src).unwrap();
            let res = validator.validate(&pset, ValidationMode::Strict);
            for err in res.validation_errors() {
                assert!(err.labels().is_some(), "no source span for the validation error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(err.clone()));
                assert!(err.source_code().is_some(), "no source code for the validation error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(err.clone()));
            }
            for warn in res.validation_warnings() {
                assert!(warn.labels().is_some(), "no source span for the validation error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(warn.clone()));
                assert!(warn.source_code().is_some(), "no source code for the validation error resulting from:\n  {src}\nerror was:\n{:?}", miette::Report::new(warn.clone()));
            }
        }
    }
}

mod issue_779 {
    use crate::Schema;
    use cool_asserts::assert_matches;
    use miette::Diagnostic;

    #[test]
    fn issue_779() {
        let json = r#"{ "" : { "actions": { "view": {} }, "entityTypes": { invalid } }}"#;
        let human = r"namespace Foo { entity User; action View; invalid }";

        assert_matches!(Schema::from_json_str(human), Err(e) => {
            assert_matches!(e.help().map(|h| h.to_string()), Some(h) => assert_eq!(h, "this API was expecting a schema in the JSON format; did you mean to use a different function, which expects the Cedar schema format?"));
        });
        assert_matches!(Schema::from_json_str(json), Err(e) => {
            assert_matches!(e.help().map(|h| h.to_string()), None, "found unexpected help message on error:\n{:?}", miette::Report::new(e)); // in particular, shouldn't suggest you meant non-JSON format, because this looks like JSON
        });
        assert_matches!(Schema::from_json_str("    "), Err(e) => {
            assert_matches!(e.help().map(|h| h.to_string()), None, "found unexpected help message on error:\n{:?}", miette::Report::new(e)); // in particular, shouldn't suggest you meant non-JSON format
        });
        assert_matches!(Schema::from_str_natural(json).map(|(s, _warnings)| s), Err(e) => {
            assert_matches!(e.help().map(|h| h.to_string()), Some(h) => assert_eq!(h, "this API was expecting a schema in the Cedar schema format; did you mean to use a different function, which expects a JSON-format Cedar schema"));
        });
        assert_matches!(Schema::from_str_natural(human).map(|(s, _warnings)| s), Err(e) => {
            assert_matches!(e.help().map(|h| h.to_string()), None, "found unexpected help message on error:\n{:?}", miette::Report::new(e)); // in particular, shouldn't suggest you meant JSON format, because this doesn't look like JSON
        });
        assert_matches!(
            Schema::from_str_natural("    ").map(|(s, _warnings)| s),
            Ok(_)
        );
    }
}

mod issue_618 {
    use std::str::FromStr;

    use crate::Policy;

    #[track_caller]
    fn round_trip(policy_src: &str) {
        let p1 = Policy::from_str(policy_src).unwrap();

        let json = p1.to_json().unwrap();

        let p2 = Policy::from_json(None, json).unwrap();
        assert_eq!(p1.to_string(), p2.to_string());
    }
    #[test]
    fn string_escapes() {
        round_trip(r#"permit(principal, action, resource) when { "\n" };"#);
        round_trip(r#"permit(principal, action, resource) when { principal has "\n" };"#);
        round_trip(r#"permit(principal, action, resource) when { principal["\n"] };"#);
        round_trip(r#"permit(principal, action, resource) when { {"\n": 0} };"#);
        round_trip(
            r#"@annotation("\n") 
permit(principal, action, resource) when { {"\n": 0} };"#,
        );
    }

    #[test]
    fn pattern_escapes() {
        round_trip(r#"permit(principal, action, resource) when { "" like "\n" };"#);
        round_trip(r#"permit(principal, action, resource) when { "" like "\*\n" };"#);
        round_trip(r#"permit(principal, action, resource) when { "\r" like "*\n" };"#);
        round_trip(r#"permit(principal, action, resource) when { "b\ra*" like "\*c*\nd" };"#);
    }

    #[test]
    fn eid_escapes() {
        round_trip(r#"permit(principal, action, resource) when { Foo::"\n" };"#);
        round_trip(r#"permit(principal, action, resource) when { Foo::"\n\r\\" };"#);
    }
}
mod issue_604 {
    use crate::Policy;
    use cedar_policy_core::parser::parse_policy_or_template_to_est;
    use cool_asserts::assert_matches;
    #[track_caller]
    fn to_json_is_ok(text: &str) {
        let policy = Policy::parse(None, text).unwrap();
        let json = policy.to_json();
        assert_matches!(json, Ok(_));
    }

    #[track_caller]
    fn make_policy_with_get_attr(attr: &str) -> String {
        format!(
            r#"
        permit(principal, action, resource) when {{ principal == resource.{attr} }};
        "#
        )
    }

    #[track_caller]
    fn make_policy_with_has_attr(attr: &str) -> String {
        format!(
            r#"
        permit(principal, action, resource) when {{ resource has {attr} }};
        "#
        )
    }

    #[test]
    fn var_as_attribute_name() {
        for attr in ["principal", "action", "resource", "context"] {
            to_json_is_ok(&make_policy_with_get_attr(attr));
            to_json_is_ok(&make_policy_with_has_attr(attr));
        }
    }

    #[track_caller]
    fn is_valid_est(text: &str) {
        let est = parse_policy_or_template_to_est(text);
        assert_matches!(est, Ok(_));
    }

    #[track_caller]
    fn is_invalid_est(text: &str) {
        let est = parse_policy_or_template_to_est(text);
        assert_matches!(est, Err(_));
    }

    #[test]
    fn keyword_as_attribute_name_err() {
        for attr in ["true", "false", "if", "then", "else", "in", "like", "has"] {
            is_invalid_est(&make_policy_with_get_attr(attr));
            is_invalid_est(&make_policy_with_has_attr(attr));
        }
    }

    #[test]
    fn keyword_as_attribute_name_ok() {
        for attr in ["permit", "forbid", "when", "unless", "_"] {
            is_valid_est(&make_policy_with_get_attr(attr));
            is_valid_est(&make_policy_with_has_attr(attr));
        }
    }
}

mod issue_606 {
    use super::{expect_err, ExpectedErrorMessageBuilder};
    use crate::{PolicyId, Template};
    use cool_asserts::assert_matches;

    #[test]
    fn est_template() {
        let est_json = serde_json::json!({
            "effect": "permit",
            "principal": { "op": "All" },
            "action": { "op": "All" },
            "resource": { "op": "All" },
            "conditions": [
                {
                    "kind": "when",
                    "body": {
                        "==": {
                            "left": { "Var": "principal" },
                            "right": { "Slot": "?principal" }
                        }
                    }
                }
            ]
        });

        let tid = PolicyId::new("t0");
        // We should get an error here after trying to construct a template with a slot in the condition
        assert_matches!(Template::from_json(Some(tid), est_json.clone()), Err(e) => {
            expect_err(
                &est_json,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error deserializing a policy/template from JSON")
                    .source("found template slot ?principal in a `when` clause")
                    .help("slots are currently unsupported in `when` clauses")
                    .build(),
            );
        });
    }
}

mod issue_619 {
    use crate::{eval_expression, Context, Entities, EntityUid, EvalResult, Policy, Request};
    use cool_asserts::assert_matches;

    /// The first issue reported in issue 619.
    /// This policy should parse properly, convert to JSON properly, and convert back from JSON properly.
    #[test]
    fn issue_619() {
        let policy = Policy::parse(
            None,
            "permit(principal, action, resource) when {1 * 2 * true};",
        )
        .unwrap();
        let json = policy.to_json().unwrap();
        let _ = Policy::from_json(None, json).unwrap();
    }

    /// Another issue from a comment: Ensure the correct error semantics of these expressions
    #[test]
    fn mult_overflows() {
        let euid: EntityUid = r#"Placeholder::"entity""#.parse().unwrap();
        let eval = |expr: &str| {
            eval_expression(
                &Request::new(
                    euid.clone(),
                    euid.clone(),
                    euid.clone(),
                    Context::empty(),
                    None,
                )
                .unwrap(),
                &Entities::empty(),
                &expr.parse().unwrap(),
            )
        };
        assert_matches!(eval(&format!("{}*{}*0", 1_i64 << 62, 1_i64 << 62)), Err(e) => {
            assert_eq!(&e.to_string(), "integer overflow while attempting to multiply the values `4611686018427387904` and `4611686018427387904`");
        });
        assert_matches!(
            eval(&format!("{}*0*{}", 1_i64 << 62, 1_i64 << 62)),
            Ok(EvalResult::Long(0))
        );
        assert_matches!(
            eval(&format!("0*{}*{}", 1_i64 << 62, 1_i64 << 62)),
            Ok(EvalResult::Long(0))
        );
    }
}

mod issue_596 {
    use super::*;

    #[test]
    fn test_all_ints() {
        test_single_int(0);
        test_single_int(i64::MAX);
        test_single_int(i64::MIN);
        test_single_int(7);
        test_single_int(-7);
    }

    fn test_single_int(x: i64) {
        for i in 0..4 {
            test_single_int_with_dashes(x, i);
        }
    }

    fn test_single_int_with_dashes(x: i64, num_dashes: usize) {
        let dashes = vec!['-'; num_dashes].into_iter().collect::<String>();
        let src = format!(r#"permit(principal, action, resource) when {{ {dashes}{x} }};"#);
        let p: Policy = src.parse().unwrap();
        let json = p.to_json().unwrap();
        let round_trip = Policy::from_json(None, json).unwrap();
        let pretty_print = format!("{round_trip}");
        assert!(pretty_print.contains(&x.to_string()));
        if x != 0 {
            let expected_dashes = if x < 0 { num_dashes + 1 } else { num_dashes };
            assert_eq!(
                pretty_print.chars().filter(|c| *c == '-').count(),
                expected_dashes
            );
        }
    }

    // Serializing a valid 64-bit int that can't be represented in double precision float
    #[test]
    fn json_bignum_1() {
        let src = r#"
        permit(
            principal,
            action == Action::"action",
            resource
          ) when {
            -9223372036854775808
          };"#;
        let p: Policy = src.parse().unwrap();
        p.to_json().unwrap();
    }

    #[test]
    fn json_bignum_1a() {
        let src = r"
        permit(principal, action, resource) when {
            (true && (-90071992547409921)) && principal
        };";
        let p: Policy = src.parse().unwrap();
        let v = p.to_json().unwrap();
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("90071992547409921"));
    }

    // Deserializing a valid 64-bit int that can't be represented in double precision float
    #[test]
    fn json_bignum_2() {
        let src = r#"{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"when","body":{"==":{"left":{".":{"left":{"Var":"principal"},"attr":"x"}},"right":{"Value":90071992547409921}}}}]}"#;
        let v: serde_json::Value = serde_json::from_str(src).unwrap();
        let p = Policy::from_json(None, v).unwrap();
        let pretty = format!("{p}");
        // Ensure the number didn't get rounded
        assert!(pretty.contains("90071992547409921"));
    }

    // Deserializing a valid 64-bit int that can't be represented in double precision float
    #[test]
    fn json_bignum_2a() {
        let src = r#"{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"when","body":{"==":{"left":{".":{"left":{"Var":"principal"},"attr":"x"}},"right":{"Value":-9223372036854775808}}}}]}"#;
        let v: serde_json::Value = serde_json::from_str(src).unwrap();
        let p = Policy::from_json(None, v).unwrap();
        let pretty = format!("{p}");
        // Ensure the number didn't get rounded
        assert!(pretty.contains("-9223372036854775808"));
    }

    // Deserializing a number that doesn't fit in 64 bit integer
    // This _should_ fail, as there's no way to do this w/out loss of precision
    #[test]
    fn json_bignum_3() {
        let src = r#"{"effect":"permit","principal":{"op":"All"},"action":{"op":"All"},"resource":{"op":"All"},"conditions":[{"kind":"when","body":{"==":{"left":{".":{"left":{"Var":"principal"},"attr":"x"}},"right":{"Value":9223372036854775808}}}}]}"#;
        let v: serde_json::Value = serde_json::from_str(src).unwrap();
        assert!(Policy::from_json(None, v).is_err());
    }
}

mod decimal_ip_constructors {
    use cool_asserts::assert_matches;

    use super::*;

    #[test]
    fn expr_ip_constructor() {
        let ip = Expression::new_ip("10.10.10.10");
        assert_matches!(ip.into_inner().expr_kind(),
            ast::ExprKind::ExtensionFunctionApp { fn_name, args} => {
                assert_eq!(fn_name, &("ip".parse().unwrap()));
                assert_eq!(args.as_ref().len(), 1);
                let arg = args.first().unwrap();
                assert_matches!(arg.expr_kind(),
                ast::ExprKind::Lit(ast::Literal::String(s)) => s.as_str() == "10.10.10.10");
            }
        );
    }

    #[test]
    fn expr_ip() {
        let ip = Expression::new_ip("10.10.10.10");
        assert_matches!(evaluate_empty(&ip),
                Ok(EvalResult::ExtensionValue(o)) => assert_eq!(&o, "10.10.10.10/32")
        );
    }

    #[test]
    fn expr_ip_network() {
        let ip = Expression::new_ip("10.10.10.10/16");
        assert_matches!(evaluate_empty(&ip),
            Ok(EvalResult::ExtensionValue(o)) => assert_eq!(&o, "10.10.10.10/16")
        );
    }

    #[test]
    fn expr_bad_ip() {
        let ip = Expression::new_ip("192.168.312.3");
        assert_matches!(evaluate_empty(&ip),
            Err(EvaluationError::FailedExtensionFunctionExecution(e)) => {
                assert_eq!(e.extension_name(), "ipaddr");
            }
        );
    }

    #[test]
    fn expr_bad_cidr() {
        let ip = Expression::new_ip("192.168.0.3/100");
        assert_matches!(evaluate_empty(&ip),
            Err(EvaluationError::FailedExtensionFunctionExecution(e)) => {
                assert_eq!(e.extension_name(), "ipaddr");
            }
        );
    }

    #[test]
    fn expr_nonsense_ip() {
        let ip = Expression::new_ip("foobar");
        assert_matches!(evaluate_empty(&ip),
            Err(EvaluationError::FailedExtensionFunctionExecution(e)) => {
                assert_eq!(e.extension_name(), "ipaddr");
            }
        );
    }

    fn evaluate_empty(expr: &Expression) -> Result<EvalResult, EvaluationError> {
        let euid: EntityUid = r#"Placeholder::"entity""#.parse().unwrap();
        let r = Request::new(euid.clone(), euid.clone(), euid, Context::empty(), None).unwrap();
        let e = Entities::empty();
        eval_expression(&r, &e, expr)
    }

    #[test]
    fn rexpr_ip_constructor() {
        let ip = RestrictedExpression::new_ip("10.10.10.10");
        assert_matches!(ip.into_inner().expr_kind(),
            ast::ExprKind::ExtensionFunctionApp { fn_name, args} => {
                assert_eq!(fn_name, &("ip".parse().unwrap()));
                assert_eq!(args.as_ref().len(), 1);
                let arg = args.first().unwrap();
                assert_matches!(arg.expr_kind(),
                ast::ExprKind::Lit(ast::Literal::String(s)) => s.as_str() == "10.10.10.10");
            }
        );
    }

    #[test]
    fn expr_decimal_constructor() {
        let decimal = Expression::new_decimal("1234.1234");
        assert_matches!(decimal.into_inner().expr_kind(),
            ast::ExprKind::ExtensionFunctionApp { fn_name, args} => {
                assert_eq!(fn_name, &("decimal".parse().unwrap()));
                assert_eq!(args.as_ref().len(), 1);
                let arg = args.first().unwrap();
                assert_matches!(arg.expr_kind(),
                ast::ExprKind::Lit(ast::Literal::String(s)) => s.as_str() == "1234.1234");
            }
        );
    }

    #[test]
    fn rexpr_decimal_constructor() {
        let decimal = RestrictedExpression::new_decimal("1234.1234");
        assert_matches!(decimal.into_inner().expr_kind(),
            ast::ExprKind::ExtensionFunctionApp { fn_name, args} => {
                assert_eq!(fn_name, &("decimal".parse().unwrap()));
                assert_eq!(args.as_ref().len(), 1);
                let arg = args.first().unwrap();
                assert_matches!(arg.expr_kind(),
                ast::ExprKind::Lit(ast::Literal::String(s)) => s.as_str() == "1234.1234");
            }
        );
    }

    #[test]
    fn valid_decimal() {
        let decimal = Expression::new_decimal("1234.1234");
        assert_matches!(evaluate_empty(&decimal),
         Ok(EvalResult::ExtensionValue(s)) => s == "1234.1234");
    }

    #[test]
    fn invalid_decimal() {
        let decimal = Expression::new_decimal("1234.12345");
        assert_matches!(evaluate_empty(&decimal),
            Err(EvaluationError::FailedExtensionFunctionExecution(e)) => {
                assert_eq!(e.extension_name(), "decimal");
            }
        );
    }
}

mod into_iter_entities {
    use super::*;
    use smol_str::SmolStr;

    #[test]
    fn into_iter_entities() {
        let test_data = r#"
        [
        {
        "uid": {"type":"User","id":"alice"},
        "attrs": {
            "age":19,
            "ip_addr":{"__extn":{"fn":"ip", "arg":"10.0.1.101"}}
        },
        "parents": [{"type":"Group","id":"admin"}]
        },
        {
        "uid": {"type":"Group","id":"admin"},
        "attrs": {},
        "parents": []
        }
        ]
        "#;

        let list = Entities::from_json_str(test_data, None).unwrap();
        let mut list_out: Vec<SmolStr> = list
            .into_iter()
            .map(|entity| entity.uid().id().escaped())
            .collect();
        list_out.sort();
        assert_eq!(list_out, &["admin", "alice"]);
    }
}

mod policy_set_est_tests {
    use itertools::{Either, Itertools};

    use super::*;

    #[test]
    fn test_partition_fold() {
        let even_or_odd = |s: &str| {
            i64::from_str(s).map(|i| {
                if i % 2 == 0 {
                    Either::Left(i)
                } else {
                    Either::Right(i)
                }
            })
        };

        let lst = ["23", "24", "75", "9320"];
        let (evens, odds) = fold_partition(lst, even_or_odd).unwrap();
        assert!(evens.into_iter().all(|i| i % 2 == 0));
        assert!(odds.into_iter().all(|i| i % 2 != 0));
    }

    #[test]
    fn test_partition_fold_err() {
        let even_or_odd = |s: &str| {
            i64::from_str_radix(s, 10).map(|i| {
                if i % 2 == 0 {
                    Either::Left(i)
                } else {
                    Either::Right(i)
                }
            })
        };

        let lst = ["23", "24", "not-a-number", "75", "9320"];
        assert!(fold_partition(lst, even_or_odd).is_err());
    }

    #[test]
    fn test_est_policyset_encoding() {
        let mut pset = PolicySet::default();
        let policy: Policy = r"permit(principal, action, resource) when { principal.foo };"
            .parse()
            .unwrap();
        pset.add(policy.new_id(PolicyId::new("policy"))).unwrap();
        let template: Template =
            r"permit(principal == ?principal, action, resource) when { principal.bar };"
                .parse()
                .unwrap();
        pset.add_template(template.new_id(PolicyId::new("template")))
            .unwrap();

        pset.link(
            PolicyId::new("template"),
            PolicyId::new("Link1"),
            HashMap::from_iter([(SlotId::principal(), r#"User::"Joe""#.parse().unwrap())]),
        )
        .unwrap();
        pset.link(
            PolicyId::new("template"),
            PolicyId::new("Link2"),
            HashMap::from_iter([(SlotId::principal(), r#"User::"Sally""#.parse().unwrap())]),
        )
        .unwrap();

        let json = pset.to_json().unwrap();

        let pset2 = PolicySet::from_json_value(json).unwrap();

        // There should be 2 policies, one static and two links
        assert_eq!(pset2.policies().count(), 3);
        let static_policy = pset2.policy(&PolicyId::new("policy")).unwrap();
        assert!(static_policy.is_static());

        let link = pset2.policy(&PolicyId::new("Link1")).unwrap();
        assert!(!link.is_static());
        assert_eq!(link.template_id(), Some(&PolicyId::new("template")));
        assert_eq!(
            link.template_links(),
            Some(HashMap::from_iter([(
                SlotId::principal(),
                r#"User::"Joe""#.parse().unwrap()
            )]))
        );

        let link = pset2.policy(&PolicyId::new("Link2")).unwrap();
        assert!(!link.is_static());
        assert_eq!(link.template_id(), Some(&PolicyId::new("template")));
        assert_eq!(
            link.template_links(),
            Some(HashMap::from_iter([(
                SlotId::principal(),
                r#"User::"Sally""#.parse().unwrap()
            )]))
        );

        let template = pset2.template(&PolicyId::new("template")).unwrap();
        assert_eq!(template.slots().count(), 1);
    }

    #[test]
    fn test_est_policyset_decoding_empty() {
        let empty = serde_json::json!({
            "templates" : {},
            "staticPolicies" : {},
            "templateLinks" : []
        });
        let empty = PolicySet::from_json_value(empty).unwrap();
        assert_eq!(empty, PolicySet::default());
    }

    #[test]
    fn test_est_policyset_decoding_single() {
        let value = serde_json::json!({
            "staticPolicies" :{
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "12UA45" }
                    },
                    "action": {
                        "op": "==",
                        "entity": { "type": "Action", "id": "view" }
                    },
                    "resource": {
                        "op": "in",
                        "entity": { "type": "Folder", "id": "abc" }
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "==": {
                                    "left": {
                                        ".": {
                                            "left": {
                                                "Var": "context"
                                            },
                                        "attr": "tls_version"
                                        }
                                    },
                                    "right": {
                                        "Value": "1.3"
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templates" : {},
            "templateLinks" : []
        });

        let policyset = PolicySet::from_json_value(value).unwrap();
        assert_eq!(policyset.templates().count(), 0);
        assert_eq!(policyset.policies().count(), 1);
        assert!(policyset.policy(&PolicyId::new("policy1")).is_some());
    }

    #[test]
    fn test_est_policyset_decoding_templates() {
        let value = serde_json::json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "12UA45" }
                    },
                    "action": {
                        "op": "==",
                        "entity": { "type": "Action", "id": "view" }
                    },
                    "resource": {
                        "op": "in",
                        "entity": { "type": "Folder", "id": "abc" }
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "==": {
                                    "left": {
                                        ".": {
                                            "left": {
                                                "Var": "context"
                                            },
                                        "attr": "tls_version"
                                        }
                                    },
                                    "right": {
                                        "Value": "1.3"
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templates":{
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
                        "?principal" : { "type" : "User", "id" : "John" }
                    }
                }
            ]
        });

        let policyset = PolicySet::from_json_value(value).unwrap();
        assert_eq!(policyset.policies().count(), 2);
        assert_eq!(policyset.templates().count(), 1);
        assert!(policyset.template(&PolicyId::new("template")).is_some());
        let link = policyset.policy(&PolicyId::new("link")).unwrap();
        assert_eq!(link.template_id(), Some(&PolicyId::new("template")));
        assert_eq!(
            link.template_links(),
            Some(HashMap::from_iter([(
                SlotId::principal(),
                r#"User::"John""#.parse().unwrap()
            )]))
        );
        if let Err(_) = policyset
            .get_linked_policies(PolicyId::new("template"))
            .unwrap()
            .exactly_one()
        {
            panic!("Should have exactly one");
        };
    }

    #[test]
    fn test_est_policyset_decoding_templates_bad_link_name() {
        let value = serde_json::json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "12UA45" }
                    },
                    "action": {
                        "op": "==",
                        "entity": { "type": "Action", "id": "view" }
                    },
                    "resource": {
                        "op": "in",
                        "entity": { "type": "Folder", "id": "abc" }
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "==": {
                                    "left": {
                                        ".": {
                                            "left": {
                                                "Var": "context"
                                            },
                                        "attr": "tls_version"
                                        }
                                    },
                                    "right": {
                                        "Value": "1.3"
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templates": {
                "template1": {
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
                    "templateId" : "non_existent",
                    "values" : {
                        "?principal" : { "type" : "User", "id" : "John" }
                    }
                }
            ]
        });

        let err = PolicySet::from_json_value(value).unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("unable to link template")
                .source("failed to find a template with id `non_existent`")
                .build(),
        );
    }

    #[test]
    fn test_est_policyset_decoding_templates_empty_env() {
        let value = serde_json::json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "12UA45" }
                    },
                    "action": {
                        "op": "==",
                        "entity": { "type": "Action", "id": "view" }
                    },
                    "resource": {
                        "op": "in",
                        "entity": { "type": "Folder", "id": "abc" }
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "==": {
                                    "left": {
                                        ".": {
                                            "left": {
                                                "Var": "context"
                                            },
                                        "attr": "tls_version"
                                        }
                                    },
                                    "right": {
                                        "Value": "1.3"
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templates": {
                "template1": {
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
                    "templateId" : "template1",
                    "values" : {},
                }
            ]
        });

        let err = PolicySet::from_json_value(value).unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("unable to link template")
                .source("the following slots were not provided as arguments: ?principal")
                .build(),
        );
    }

    #[test]
    fn test_est_policyset_decoding_templates_bad_dup_links() {
        let value = serde_json::json!({
            "staticPolicies" : {},
            "templates": {
                "template1": {
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
                    "templateId" : "template1",
                    "values" : {
                        "?principal" : { "type" : "User", "id" : "John" },
                    }
                },
                {
                    "newId" : "link",
                    "templateId" : "template1",
                    "values" : {
                        "?principal" : { "type" : "User", "id" : "John" },
                    }
                }
            ]
        });

        let err = PolicySet::from_json_value(value).unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("unable to link template")
                .source("template-linked policy id `link` conflicts with an existing policy id")
                .build(),
        );
    }

    #[test]
    fn test_est_policyset_decoding_templates_bad_extra_vals() {
        let value = serde_json::json!({
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "12UA45" }
                    },
                    "action": {
                        "op": "==",
                        "entity": { "type": "Action", "id": "view" }
                    },
                    "resource": {
                        "op": "in",
                        "entity": { "type": "Folder", "id": "abc" }
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "==": {
                                    "left": {
                                        ".": {
                                            "left": {
                                                "Var": "context"
                                            },
                                        "attr": "tls_version"
                                        }
                                    },
                                    "right": {
                                        "Value": "1.3"
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templates": {
                "template1": {
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
                    "templateId" : "template1",
                    "values" : {
                        "?principal" : { "type" : "User", "id" : "John" },
                        "?resource" : { "type" : "Box", "id" : "ABC" }
                    }
                }
            ]}
        );

        let err = PolicySet::from_json_value(value).unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("unable to link template")
                .source("the following slots were provided as arguments, but did not exist in the template: ?resource")
                .build(),
        );
    }

    #[test]
    fn test_est_policyset_decoding_templates_bad_dup_vals() {
        let value = r#" {
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "12UA45" }
                    },
                    "action": {
                        "op": "==",
                        "entity": { "type": "Action", "id": "view" }
                    },
                    "resource": {
                        "op": "in",
                        "entity": { "type": "Folder", "id": "abc" }
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "==": {
                                    "left": {
                                        ".": {
                                            "left": {
                                                "Var": "context"
                                            },
                                        "attr": "tls_version"
                                        }
                                    },
                                    "right": {
                                        "Value": "1.3"
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templates" : {
                "template1": {
                    "effect" : "permit",
                    "principal" : {
                        "op" : "==",
                        "slot" : "?principal"
                    },
                    "action" : {
                        "op" : "all"
                    },
                    "resource" : {
                        "op" : "all"
                    },
                    "conditions": []
                }
            },
            "templateLinks" : [
                {
                    "newId" : "link",
                    "templateId" : "template1",
                    "values" : {
                        "?principal" : { "type" : "User", "id" : "John" },
                        "?principal" : { "type" : "User", "id" : "Duplicate" }
                    }
                }
            ]}"#;

        let err = PolicySet::from_json_str(value).unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                "error serializing/deserializing policy set to/from JSON",
            )
            .source("invalid entry: found duplicate key at line 62 column 21")
            .build(),
        );
    }

    #[test]
    fn test_est_policyset_decoding_templates_bad_euid() {
        let value = r#" {
            "staticPolicies": {
                "policy1": {
                    "effect": "permit",
                    "principal": {
                        "op": "==",
                        "entity": { "type": "User", "id": "12UA45" }
                    },
                    "action": {
                        "op": "==",
                        "entity": { "type": "Action", "id": "view" }
                    },
                    "resource": {
                        "op": "in",
                        "entity": { "type": "Folder", "id": "abc" }
                    },
                    "conditions": [
                        {
                            "kind": "when",
                            "body": {
                                "==": {
                                    "left": {
                                        ".": {
                                            "left": {
                                                "Var": "context"
                                            },
                                        "attr": "tls_version"
                                        }
                                    },
                                    "right": {
                                        "Value": "1.3"
                                    }
                                }
                            }
                        }
                    ]
                }
            },
            "templates" : {
                "template1": {
                    "effect" : "permit",
                    "principal" : {
                        "op" : "==",
                        "slot" : "?principal"
                    },
                    "action" : {
                        "op" : "all"
                    },
                    "resource" : {
                        "op" : "all"
                    },
                    "conditions": []
                }
            },
            "templateLinks" : [
                {
                    "newId" : "link",
                    "templateId" : "template1",
                    "values" : {
                        "?principal" : { "type" : "User" }
                    }
                }
            ]}"#;

        let err = PolicySet::from_json_str(value).unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("error serializing/deserializing policy set to/from JSON")
                .source(r#"while parsing a template link, expected a literal entity reference, but got `{"type":"User"}` at line 61 column 21"#)
                .build(),
        );
    }
}

// PANIC SAFETY unit tests
#[allow(clippy::indexing_slicing)]
mod authorization_error_tests {
    use super::*;

    #[test]
    fn test_policy_evaluation_error() {
        let authorizer = Authorizer::new();
        let request = Request::new(
            EntityUid::from_strs("Principal", "p"),
            EntityUid::from_strs("Action", "a"),
            EntityUid::from_strs("Resource", "r"),
            Context::empty(),
            None,
        )
        .unwrap();

        let e = r#"[
            {
                "uid": {"type":"Principal","id":"p"},
                "attrs": {},
                "parents": []
            },
            {
                "uid": {"type":"Action","id":"a"},
                "attrs": {},
                "parents": []
            },
            {
                "uid": {"type":"Resource","id":"r"},
                "attrs": {},
                "parents": []
            }
        ]"#;
        let entities = Entities::from_json_str(e, None).expect("entity error");

        let mut pset = PolicySet::new();
        let static_policy = Policy::parse(
            Some(PolicyId::new("id0")),
            "permit(principal,action,resource) when {principal.foo == 1};",
        )
        .expect("Failed to parse");
        pset.add(static_policy).expect("Failed to add");

        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Deny);
        assert_eq!(response.diagnostics().reason().count(), 0);
        let errs = response.diagnostics().errors().collect::<Vec<_>>();
        assert_eq!(errs.len(), 1);
        expect_err(
            "",
            &Report::new(errs[0].clone()),
            &ExpectedErrorMessageBuilder::error(r#"error while evaluating policy `id0`: `Principal::"p"` does not have the attribute `foo`"#)
                .build(),
        );
    }
}

mod request_validation_tests {
    use serde_json::json;

    use super::*;

    fn schema() -> Schema {
        Schema::from_json_value(json!(
        {
            "": {
                "entityTypes": {
                    "Principal": {},
                    "Resource": {},
                },
                "actions": {
                    "action": {
                        "appliesTo": {
                            "principalTypes": ["Principal"],
                            "resourceTypes": ["Resource"],
                            "context": {
                                "type": "Record",
                                "attributes": {
                                    "foo": {
                                        "type": "String"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        ))
        .unwrap()
    }

    #[test]
    fn undeclared_action() {
        let schema = schema();
        let err = Request::new(
            EntityUid::from_strs("Principal", "principal"),
            EntityUid::from_strs("Action", "undeclared"),
            EntityUid::from_strs("Resource", "resource"),
            Context::empty(),
            Some(&schema),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                r#"request's action `Action::"undeclared"` is not declared in the schema"#,
            )
            .build(),
        );
    }

    #[test]
    fn undeclared_principal_type() {
        let schema = schema();
        let err = Request::new(
            EntityUid::from_strs("Undeclared", "principal"),
            EntityUid::from_strs("Action", "action"),
            EntityUid::from_strs("Resource", "resource"),
            Context::empty(),
            Some(&schema),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                "principal type `Undeclared` is not declared in the schema",
            )
            .build(),
        );
    }

    #[test]
    fn undeclared_resource_type() {
        let schema = schema();
        let err = Request::new(
            EntityUid::from_strs("Principal", "principal"),
            EntityUid::from_strs("Action", "action"),
            EntityUid::from_strs("Undeclared", "resource"),
            Context::empty(),
            Some(&schema),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                "resource type `Undeclared` is not declared in the schema",
            )
            .build(),
        );
    }

    #[test]
    fn invalid_principal_type() {
        let schema = schema();
        let err = Request::new(
            EntityUid::from_strs("Resource", "principal"),
            EntityUid::from_strs("Action", "action"),
            EntityUid::from_strs("Resource", "resource"),
            Context::empty(),
            Some(&schema),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                r#"principal type `Resource` is not valid for `Action::"action"`"#,
            )
            .build(),
        );
    }

    #[test]
    fn invalid_resource_type() {
        let schema = schema();
        let err = Request::new(
            EntityUid::from_strs("Principal", "principal"),
            EntityUid::from_strs("Action", "action"),
            EntityUid::from_strs("Principal", "resource"),
            Context::empty(),
            Some(&schema),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                r#"resource type `Principal` is not valid for `Action::"action"`"#,
            )
            .build(),
        );
    }

    #[test]
    fn invalid_context() {
        let schema = schema();
        let err = Request::new(
            EntityUid::from_strs("Principal", "principal"),
            EntityUid::from_strs("Action", "action"),
            EntityUid::from_strs("Resource", "resource"),
            Context::empty(),
            Some(&schema),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                r#"context `<first-class record with 0 fields>` is not valid for `Action::"action"`"#,
            )
            .build(),
        );

        let err = Request::new(
            EntityUid::from_strs("Principal", "principal"),
            EntityUid::from_strs("Action", "action"),
            EntityUid::from_strs("Resource", "resource"),
            Context::from_json_value(json!({"foo": 123}), None)
                .expect("context creation should have succeeded"),
            Some(&schema),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                r#"context `<first-class record with 1 fields>` is not valid for `Action::"action"`"#,
            )
            .build(),
        );
    }
}

mod context_tests {
    use cool_asserts::assert_matches;
    use serde_json::json;

    use super::*;

    fn schema() -> Schema {
        Schema::from_json_value(json!(
            {
                "": {
                    "entityTypes": {
                        "User" : {}
                    },
                    "actions": {
                        "action": {
                            "appliesTo": {
                                "principalTypes": ["User"],
                                "resourceTypes": ["User"],
                                "context": {
                                    "type": "Record",
                                    "attributes": {
                                        "foo": { "type": "String" },
                                        "bar": { "type": "Extension", "name": "decimal", "required": false }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ))
            .unwrap()
    }

    #[test]
    fn schema_based_parsing() {
        let schema = schema();

        // ok
        Context::from_json_value(
            json!({"foo": "some string", "bar": { "__extn": { "fn": "decimal", "arg": "1.23" } }}),
            Some((&schema, &EntityUid::from_strs("Action", "action"))),
        )
        .expect("context creation should have succeeded");

        // ok - and 1.23 is parsed as a decimal instead of a string
        Context::from_json_value(
            json!({"foo": "some string", "bar": "1.23"}),
            Some((&schema, &EntityUid::from_strs("Action", "action"))),
        )
        .expect("context creation should have succeeded");

        // ok (despite the fact that "foo" has the incorrect type) - the schema for
        // `Context::from_json_value` is used for schema-based parsing, not validation
        Context::from_json_value(
            json!({"foo": 123}),
            Some((&schema, &EntityUid::from_strs("Action", "action"))),
        )
        .expect("context creation should have succeeded");

        // error - missing a required attribute is not allowed
        let err = Context::from_json_value(
            json!({"xxx": 123}),
            Some((&schema, &EntityUid::from_strs("Action", "action"))),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                "while parsing context, expected the record to have an attribute `foo`, but it does not",
            )
            .build(),
        );

        // error - including an undefined attribute is not allowed
        let err = Context::from_json_value(
            json!({"foo": "some string", "xxx": "1.23"}),
            Some((&schema, &EntityUid::from_strs("Action", "action"))),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                "while parsing context, record attribute `xxx` should not exist according to the schema",
            )
            .build(),
        );
    }

    #[test]
    fn missing_action() {
        let schema = schema();
        let err = Context::from_json_value(
            json!({"foo": "some string"}),
            Some((&schema, &EntityUid::from_strs("Action", "foo"))),
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(
                r#"action `Action::"foo"` does not exist in the supplied schema"#,
            )
            .build(),
        );
    }

    #[test]
    fn context_creation_errors() {
        let err = Context::from_json_value(json!("not_a_record"), None).unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error(r#"expression is not a record: "not_a_record""#)
                .build(),
        );

        let err = Context::from_json_value(
            json!({"foo": { "__extn": { "fn": "ip", "arg": "not_an_ip_address" }}}),
            None,
        )
        .unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("error while evaluating `ipaddr` extension function: invalid IP address: not_an_ip_address")
                .build(),
        );

        let pairs = vec![
            (
                String::from("key1"),
                RestrictedExpression::new_string("foo".into()),
            ),
            (String::from("key1"), RestrictedExpression::new_bool(true)),
        ];
        let err = Context::from_pairs(pairs).unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("duplicate key `key1` in context").build(),
        );
    }

    #[test]
    fn merge_contexts() {
        let context_pt_1 = Context::from_json_value(json!({"key1": "foo", "key2": true}), None)
            .expect("context creation should have succeeded");
        let pairs = vec![(String::from("key3"), RestrictedExpression::new_long(42))];
        let context_pt_2 =
            Context::from_pairs(pairs).expect("context creation should have succeeded");

        let context = context_pt_1
            .merge(context_pt_2)
            .expect("context merge should have succeeded");
        let values = context.into_iter();
        for (k, v) in values {
            match k.as_ref() {
                "key1" => {
                    assert_matches!(
                        v.into_inner().expr_kind(),
                        ast::ExprKind::Lit(ast::Literal::String(s)) => {
                            assert_eq!(s.as_str(), "foo");
                        }
                    );
                }
                "key2" => {
                    assert_matches!(
                        v.into_inner().expr_kind(),
                        ast::ExprKind::Lit(ast::Literal::Bool(true)),
                    );
                }
                "key3" => {
                    assert_matches!(
                        v.into_inner().expr_kind(),
                        ast::ExprKind::Lit(ast::Literal::Long(42)),
                    );
                }
                _ => {
                    panic!("unexpected key `{k}`");
                }
            }
        }
    }

    #[test]
    fn merge_contexts_duplicate_keys() {
        let context_pt_1 = Context::from_json_value(json!({"key1": "foo", "key2": true}), None)
            .expect("context creation should have succeeded");
        let pairs = vec![(String::from("key2"), RestrictedExpression::new_long(42))];
        let context_pt_2 =
            Context::from_pairs(pairs).expect("context creation should have succeeded");

        let err = context_pt_1.merge(context_pt_2).unwrap_err();
        expect_err(
            "",
            &Report::new(err),
            &ExpectedErrorMessageBuilder::error("duplicate key `key2` in context").build(),
        );
    }
}
