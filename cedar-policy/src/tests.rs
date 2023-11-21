#![cfg(test)]
// PANIC SAFETY unit tests
#![allow(clippy::panic)]

use super::*;

pub use ast::Effect;
pub use authorizer::Decision;
use cedar_policy_core::ast;
use cedar_policy_core::authorizer;
pub use cedar_policy_core::authorizer::AuthorizationError;
use cedar_policy_core::entities::{self};
pub use cedar_policy_core::evaluator::{EvaluationError, EvaluationErrorKind};
pub use cedar_policy_core::extensions;
pub use cedar_policy_core::parser::err::ParseErrors;
pub use cedar_policy_validator::{
    TypeErrorKind, UnsupportedFeature, ValidationErrorKind, ValidationWarningKind,
};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

pub use super::api::Response;

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
        assert_eq!(euid.type_name().to_string(), r#"Test::User"#);
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
        let euid = match policy.principal_constraint() {
            PrincipalConstraint::Eq(euid) => euid,
            _ => panic!("expected Eq constraint"),
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
        let euid = match policy.principal_constraint() {
            PrincipalConstraint::Eq(euid) => euid,
            _ => panic!("expected Eq constraint"),
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
        let result = EntityTypeName::from_str("I'm an invalid name");

        assert_matches!(result, Err(ParseErrors(_)));
        let error = result.err().unwrap();
        assert!(error.to_string().contains("invalid token"));
    }

    /// parsing an `EntityUid` from string
    #[test]
    fn parse_euid() {
        let parsed_eid: EntityUid = r#"Test::User::"bobby""#.parse().expect("Failed to parse");
        assert_eq!(parsed_eid.id().as_ref(), r#"bobby"#);
        assert_eq!(parsed_eid.type_name().to_string(), r#"Test::User"#);
    }

    /// parsing an `EntityUid` from string, including escapes
    #[test]
    fn parse_euid_with_escape() {
        // the EntityUid string has an escaped single-quote and escaped double-quote
        let parsed_eid: EntityUid = r#"Test::User::"b\'ob\"by""#.parse().expect("Failed to parse");
        // the escapes were interpreted:
        //   the EntityId has single-quote and double-quote characters (but no backslash characters)
        assert_eq!(parsed_eid.id().as_ref(), r#"b'ob"by"#);
        assert_eq!(parsed_eid.type_name().to_string(), r#"Test::User"#);
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
        assert_eq!(parsed_euid.id().as_ref(), r#"b'obby's sister"#);
        assert_eq!(parsed_euid.type_name().to_string(), r#"Test::User"#);
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
        assert_eq!(parsed_euid.id().as_ref(), r#"b'ob"#);
        let reparsed: EntityUid = format!("{parsed_euid}")
            .parse()
            .expect("failed to roundtrip");
        assert_eq!(reparsed.id().as_ref(), r#"b'ob"#);
    }

    #[test]
    fn accessing_unspecified_entity_returns_none() {
        let c = Context::empty();
        let request = Request::new(None, None, None, c, None).unwrap();
        let p = request.principal();
        let a = request.action();
        let r = request.resource();
        assert_matches!(p, None);
        assert_matches!(a, None);
        assert_matches!(r, None);
    }
}

mod head_constraints_tests {
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
            PrincipalConstraint::IsIn(EntityTypeName::from_str("T").unwrap(), euid.clone())
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
        let template = Template::parse(Some("Id".to_string()), src).unwrap();

        pset.add_template(template).unwrap();

        let link_id = PolicyId::from_str("link").unwrap();
        pset.link(PolicyId::from_str("Id").unwrap(), link_id.clone(), values)
            .unwrap();
        pset.policy(&link_id).unwrap().clone()
    }
}

/// Tests in this module are adapted from Core's `policy_set.rs` tests
mod policy_set_tests {
    use super::*;
    use ast::LinkingError;
    use cool_asserts::assert_matches;

    #[test]
    fn link_conflicts() {
        let mut pset = PolicySet::new();
        let p1 = Policy::parse(Some("id".into()), "permit(principal,action,resource);")
            .expect("Failed to parse");
        pset.add(p1).expect("Failed to add");
        let template = Template::parse(
            Some("t".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template).expect("Add failed");

        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();

        let before_link = pset.clone();
        let r = pset.link(
            PolicyId::from_str("t").unwrap(),
            PolicyId::from_str("id").unwrap(),
            env,
        );

        assert_matches!(
            r,
            Err(PolicySetError::LinkingError(LinkingError::PolicyIdConflict { id })) =>{
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
        let static_policy = Policy::parse(Some("id".into()), "permit(principal,action,resource);")
            .expect("Failed to parse");
        pset.add(static_policy).expect("Failed to add");

        let template = Template::parse(
            Some("t".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template).expect("Failed to add");

        let env1: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test1"))).collect();
        pset.link(
            PolicyId::from_str("t").unwrap(),
            PolicyId::from_str("link").unwrap(),
            env1,
        )
        .expect("Failed to link");

        let env2: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test2"))).collect();

        let err = pset
            .link(
                PolicyId::from_str("t").unwrap(),
                PolicyId::from_str("link").unwrap(),
                env2.clone(),
            )
            .expect_err("Should have failed due to conflict with existing link id");
        match err {
            PolicySetError::LinkingError(_) => (),
            e => panic!("Wrong error: {e}"),
        }

        pset.link(
            PolicyId::from_str("t").unwrap(),
            PolicyId::from_str("link2").unwrap(),
            env2,
        )
        .expect("Failed to link");

        let template2 = Template::parse(
            Some("t".into()),
            "forbid(principal, action, resource == ?resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template2)
            .expect_err("should have failed due to conflict on template id");
        let template2 = Template::parse(
            Some("t2".into()),
            "forbid(principal, action, resource == ?resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template2)
            .expect("Failed to add template");
        let env3: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::resource(), EntityUid::from_strs("Test", "test3"))).collect();

        pset.link(
            PolicyId::from_str("t").unwrap(),
            PolicyId::from_str("unique3").unwrap(),
            env3.clone(),
        )
        .expect_err("should have failed due to conflict on template id");

        pset.link(
            PolicyId::from_str("t2").unwrap(),
            PolicyId::from_str("unique3").unwrap(),
            env3,
        )
        .expect("should succeed with unique ids");
    }

    #[test]
    fn policyset_remove() {
        let authorizer = Authorizer::new();
        let request = Request::new(
            Some(EntityUid::from_strs("Test", "test")),
            Some(EntityUid::from_strs("Action", "a")),
            Some(EntityUid::from_strs("Resource", "b")),
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
        let static_policy = Policy::parse(Some("id".into()), "permit(principal,action,resource);")
            .expect("Failed to parse");
        pset.add(static_policy).expect("Failed to add");

        //Allow
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Allow);

        pset.remove_static(PolicyId::from_str("id").unwrap())
            .expect("Failed to remove static policy");

        //Deny
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Deny);

        let template = Template::parse(
            Some("t".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Failed to parse");
        pset.add_template(template).expect("Failed to add");

        let linked_policy_id = PolicyId::from_str("linked").unwrap();
        let env1: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(
            PolicyId::from_str("t").unwrap(),
            linked_policy_id.clone(),
            env1,
        )
        .expect("Failed to link");

        //Allow
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Allow);

        assert_matches!(
            pset.remove_static(PolicyId::from_str("t").unwrap()),
            Err(PolicySetError::PolicyNonexistentError(_))
        );

        let result = pset.unlink(linked_policy_id.clone());
        assert_matches!(result, Ok(_));

        assert_matches!(
            pset.remove_static(PolicyId::from_str("t").unwrap()),
            Err(PolicySetError::PolicyNonexistentError(_))
        );

        //Deny
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Deny);

        let env1: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(
            PolicyId::from_str("t").unwrap(),
            linked_policy_id.clone(),
            env1,
        )
        .expect("Failed to link");

        //Allow
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Allow);

        //Can't remove template that is still linked
        assert_matches!(
            pset.remove_template(PolicyId::from_str("t").unwrap()),
            Err(PolicySetError::RemoveTemplateWithActiveLinksError(_))
        );

        //Unlink first, then remove
        let result = pset.unlink(linked_policy_id);
        assert_matches!(result, Ok(_));
        pset.remove_template(PolicyId::from_str("t").unwrap())
            .expect("Failed to remove policy template");

        //Deny
        let response = authorizer.is_authorized(&request, &pset, &entities);
        assert_eq!(response.decision(), Decision::Deny);
    }

    #[test]
    fn pset_removal_prop_test_1() {
        let template = Template::parse(
            Some("policy0".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(
            PolicyId::from_str("policy0").unwrap(),
            PolicyId::from_str("policy3").unwrap(),
            env,
        )
        .unwrap();
        let template = Template::parse(
            Some("policy3".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");

        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined { .. })
        );
        assert_matches!(
            pset.remove_static(PolicyId::from_str("policy3").unwrap()),
            Err(PolicySetError::PolicyNonexistentError(_))
        );
        assert_matches!(
            pset.remove_template(PolicyId::from_str("policy3").unwrap()),
            Err(PolicySetError::TemplateNonexistentError(_))
        );
        //Should not panic
    }

    #[test]
    fn pset_requests() {
        let template = Template::parse(
            Some("template".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let static_policy = Policy::parse(
            Some("static".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        pset.add(static_policy).unwrap();
        pset.link(
            PolicyId::from_str("template").unwrap(),
            PolicyId::from_str("linked").unwrap(),
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
            Some("static".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        let mut pset = PolicySet::new();
        pset.add(static_policy).unwrap();

        let before_link = pset.clone();
        let result = pset.link(
            PolicyId::from_str("static").unwrap(),
            PolicyId::from_str("linked").unwrap(),
            HashMap::new(),
        );
        assert_matches!(result, Err(PolicySetError::ExpectedTemplate));
        assert_eq!(
            pset, before_link,
            "A failed link shouldn't mutate the policy set"
        );
    }

    #[test]
    fn link_linked_policy() {
        let template = Template::parse(
            Some("template".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();

        pset.link(
            PolicyId::from_str("template").unwrap(),
            PolicyId::from_str("linked").unwrap(),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();

        let before_link = pset.clone();
        let result = pset.link(
            PolicyId::from_str("linked").unwrap(),
            PolicyId::from_str("linked2").unwrap(),
            HashMap::new(),
        );
        assert_matches!(result, Err(PolicySetError::ExpectedTemplate));
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
                    ty: ast::EntityType::Specified("test_entity_type".parse().unwrap()),
                },
            )),
            ast::PolicyID::from_smolstr("static".into()),
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
            Some("template".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();

        let linked_policy_id = PolicyId::from_str("linked").unwrap();
        pset.link(
            PolicyId::from_str("template").unwrap(),
            linked_policy_id.clone(),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();

        let authorizer = Authorizer::new();
        let request = Request::new(
            Some(EntityUid::from_strs("Test", "test")),
            Some(EntityUid::from_strs("Action", "a")),
            Some(EntityUid::from_strs("Resource", "b")),
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
        assert_matches!(result, Err(PolicySetError::LinkNonexistentError(_)));
    }

    #[test]
    fn get_linked_policy() {
        let mut pset = PolicySet::new();

        let template = Template::parse(
            Some("template".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        pset.add_template(template).unwrap();

        let linked_policy_id = PolicyId::from_str("linked").unwrap();
        pset.link(
            PolicyId::from_str("template").unwrap(),
            linked_policy_id.clone(),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();

        //add link, count 1
        assert_eq!(
            pset.get_linked_policies(PolicyId::from_str("template").unwrap())
                .unwrap()
                .count(),
            1
        );
        let result = pset.unlink(linked_policy_id.clone());
        assert_matches!(result, Ok(_));
        //remove link, count 0
        assert_eq!(
            pset.get_linked_policies(PolicyId::from_str("template").unwrap())
                .unwrap()
                .count(),
            0
        );
        let result = pset.unlink(linked_policy_id.clone());
        assert_matches!(result, Err(PolicySetError::LinkNonexistentError(_)));

        pset.link(
            PolicyId::from_str("template").unwrap(),
            linked_policy_id.clone(),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();
        assert_eq!(
            pset.get_linked_policies(PolicyId::from_str("template").unwrap())
                .unwrap()
                .count(),
            1
        );
        pset.link(
            PolicyId::from_str("template").unwrap(),
            PolicyId::from_str("linked2").unwrap(),
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect(),
        )
        .unwrap();
        assert_eq!(
            pset.get_linked_policies(PolicyId::from_str("template").unwrap())
                .unwrap()
                .count(),
            2
        );

        //Can't re-add template
        let template = Template::parse(
            Some("template".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined { .. })
        );

        //Add another template
        let template = Template::parse(
            Some("template2".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        pset.add_template(template).unwrap();

        //template2 count 0
        assert_eq!(
            pset.get_linked_policies(PolicyId::from_str("template2").unwrap())
                .unwrap()
                .count(),
            0
        );

        //template count 2
        assert_eq!(
            pset.get_linked_policies(PolicyId::from_str("template").unwrap())
                .unwrap()
                .count(),
            2
        );

        //Can't remove template
        assert_matches!(
            pset.remove_template(PolicyId::from_str("template").unwrap()),
            Err(PolicySetError::RemoveTemplateWithActiveLinksError(_))
        );

        //Can't add policy named template
        let illegal_template_policy = Policy::parse(
            Some("template".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        assert_matches!(
            pset.add(illegal_template_policy),
            Err(PolicySetError::AlreadyDefined { .. })
        );

        //Can't add policy named linked
        let illegal_linked_policy = Policy::parse(
            Some("linked".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        assert_matches!(
            pset.add(illegal_linked_policy),
            Err(PolicySetError::AlreadyDefined { .. })
        );

        //Can add policy named `policy`
        let static_policy = Policy::parse(
            Some("policy".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        pset.add(static_policy).unwrap();

        //Can remove `policy`
        pset.remove_static(PolicyId::from_str("policy").unwrap())
            .expect("should be able to remove policy");

        //Cannot remove "linked"
        assert_matches!(
            pset.remove_static(PolicyId::from_str("linked").unwrap()),
            Err(PolicySetError::PolicyNonexistentError(_))
        );

        //Cannot remove "template"
        assert_matches!(
            pset.remove_static(PolicyId::from_str("template").unwrap()),
            Err(PolicySetError::PolicyNonexistentError(_))
        );

        //template count 2
        assert_eq!(
            pset.get_linked_policies(PolicyId::from_str("template").unwrap())
                .unwrap()
                .count(),
            2
        );

        //unlink one policy, template count 1
        let result = pset.unlink(linked_policy_id);
        assert_matches!(result, Ok(_));
        assert_eq!(
            pset.get_linked_policies(PolicyId::from_str("template").unwrap())
                .unwrap()
                .count(),
            1
        );

        //remove template2
        assert_matches!(
            pset.remove_template(PolicyId::from_str("template2").unwrap()),
            Ok(_)
        );

        //can't remove template1
        assert_matches!(
            pset.remove_template(PolicyId::from_str("template").unwrap()),
            Err(PolicySetError::RemoveTemplateWithActiveLinksError(_))
        );

        //unlink other policy, template count 0
        let result = pset.unlink(PolicyId::from_str("linked2").unwrap());
        assert_matches!(result, Ok(_));
        assert_eq!(
            pset.get_linked_policies(PolicyId::from_str("template").unwrap())
                .unwrap()
                .count(),
            0
        );

        //remove template
        assert_matches!(
            pset.remove_template(PolicyId::from_str("template").unwrap()),
            Ok(_)
        );

        //can't get count for nonexistent template
        assert_matches!(
            pset.get_linked_policies(PolicyId::from_str("template").unwrap())
                .err()
                .unwrap(),
            PolicySetError::TemplateNonexistentError(_)
        );
    }

    #[test]
    fn pset_add_conflict() {
        let template = Template::parse(
            Some("policy0".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(
            PolicyId::from_str("policy0").unwrap(),
            PolicyId::from_str("policy1").unwrap(),
            env,
        )
        .unwrap();

        //fails for template; static
        let static_policy = Policy::parse(
            Some("policy0".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        assert_matches!(
            pset.add(static_policy),
            Err(PolicySetError::AlreadyDefined { .. })
        );

        //fails for link; static
        let static_policy = Policy::parse(
            Some("policy1".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        assert_matches!(
            pset.add(static_policy),
            Err(PolicySetError::AlreadyDefined { .. })
        );

        //fails for static; static
        let static_policy = Policy::parse(
            Some("policy2".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        pset.add(static_policy.clone()).unwrap();
        assert_matches!(
            pset.add(static_policy),
            Err(PolicySetError::AlreadyDefined { .. })
        );
    }

    #[test]
    fn pset_add_template_conflict() {
        let template = Template::parse(
            Some("policy0".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();
        pset.link(
            PolicyId::from_str("policy0").unwrap(),
            PolicyId::from_str("policy3").unwrap(),
            env,
        )
        .unwrap();

        //fails for link; template
        let template = Template::parse(
            Some("policy3".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined { .. })
        );

        //fails for template; template
        let template = Template::parse(
            Some("policy0".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined { .. })
        );

        //fails for static; template
        let static_policy = Policy::parse(
            Some("policy1".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        pset.add(static_policy).unwrap();
        let template = Template::parse(
            Some("policy1".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        assert_matches!(
            pset.add_template(template),
            Err(PolicySetError::AlreadyDefined { .. })
        );
    }

    #[test]
    fn pset_link_conflict() {
        let template = Template::parse(
            Some("policy0".into()),
            "permit(principal == ?principal, action, resource);",
        )
        .expect("Template Parse Failure");
        let mut pset = PolicySet::new();
        pset.add_template(template).unwrap();
        let env: HashMap<SlotId, EntityUid> =
            std::iter::once((SlotId::principal(), EntityUid::from_strs("Test", "test"))).collect();

        //fails for link; link
        pset.link(
            PolicyId::from_str("policy0").unwrap(),
            PolicyId::from_str("policy3").unwrap(),
            env.clone(),
        )
        .unwrap();
        assert_matches!(
            pset.link(
                PolicyId::from_str("policy0").unwrap(),
                PolicyId::from_str("policy3").unwrap(),
                env.clone(),
            ),
            Err(PolicySetError::LinkingError(
                LinkingError::PolicyIdConflict { .. }
            ))
        );

        //fails for template; link
        assert_matches!(
            pset.link(
                PolicyId::from_str("policy0").unwrap(),
                PolicyId::from_str("policy0").unwrap(),
                env.clone(),
            ),
            Err(PolicySetError::LinkingError(
                LinkingError::PolicyIdConflict { .. }
            ))
        );

        //fails for static; link
        let static_policy = Policy::parse(
            Some("policy1".into()),
            "permit(principal, action, resource);",
        )
        .expect("Static parse failure");
        pset.add(static_policy).unwrap();
        assert_matches!(
            pset.link(
                PolicyId::from_str("policy0").unwrap(),
                PolicyId::from_str("policy1").unwrap(),
                env,
            ),
            Err(PolicySetError::LinkingError(
                LinkingError::PolicyIdConflict { .. }
            ))
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
            Schema::from_json_value(json!(
                // Written as a string because duplicate entity types are detected
                // by the serde-json string parser.
                r#""{"": {
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
            )),
            Err(SchemaError::Serde(_))
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

    fn validate_entity(entity: Entity, schema: &Schema) -> Result<(), entities::EntitiesError> {
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
        validate_entity(entity, &schema()).unwrap();
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
            Ok(_) => panic!("expected an error due to extraneous parent"),
            Err(e) => {
                assert!(
                    e.to_string().contains(r#"`Employee::"123"` is not allowed to have an ancestor of type `Manager` according to the schema"#),
                    "actual error message was {e}",
                )
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
            Ok(_) => panic!("expected an error due to missing attribute `numDirectReports`"),
            Err(e) => {
                assert!(
                    e.to_string().contains(r#"expected entity `Employee::"123"` to have attribute `numDirectReports`, but it does not"#),
                    "actual error message was {e}",
                )
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
            Ok(_) => panic!("expected an error due to extraneous attribute"),
            Err(e) => {
                assert!(
                    e.to_string().contains(r#"attribute `extra` on `Employee::"123"` should not exist according to the schema"#),
                    "actual error message was {e}",
                )
            }
        }

        let entity = Entity::new_no_attrs(EntityUid::from_strs("Manager", "jane"), HashSet::new());
        match validate_entity(entity, &schema) {
            Ok(_) => panic!("expected an error due to unexpected entity type"),
            Err(e) => {
                assert!(
                    e.to_string().contains(r#"entity `Manager::"jane"` has type `Manager` which is not declared in the schema"#),
                    "actual error message was {e}",
                )
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
    use cool_asserts::assert_matches;
    use serde_json::json;

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
        assert!(
            err.to_string().contains(r#"in attribute `numDirectReports` on `Employee::"12UA45"`, type mismatch: value was expected to have type long, but actually has type string: `"3"`"#),
            "actual error message was {err}"
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
        assert!(
            err.to_string()
                .contains(r#"in attribute `manager` on `Employee::"12UA45"`, expected a literal entity reference, but got `"34FB87"`"#),
            "actual error message was {err}"
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
        assert!(
            err.to_string().contains(r#"in attribute `hr_contacts` on `Employee::"12UA45"`, type mismatch: value was expected to have type (set of `HR`), but actually has type record with attributes: {"id" => (optional) string, "type" => (optional) string}: `{"id": "aaaaa", "type": "HR"}`"#),
            "actual error message was {err}"
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
        assert!(
            err.to_string().contains(r#"in attribute `manager` on `Employee::"12UA45"`, type mismatch: value was expected to have type `Employee`, but actually has type `HR`: `HR::"34FB87"`"#),
            "actual error message was {err}"
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
        assert!(
            err.to_string().contains(r#"in attribute `home_ip` on `Employee::"12UA45"`, type mismatch: value was expected to have type ipaddr, but actually has type decimal: `decimal("3.33")`"#),
            "actual error message was {err}"
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
        assert!(
            err.to_string().contains(r#"in attribute `json_blob` on `Employee::"12UA45"`, expected the record to have an attribute `inner2`, but it does not"#),
            "actual error message was {err}"
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
        assert!(
            err.to_string().contains(r#"in attribute `json_blob` on `Employee::"12UA45"`, type mismatch: value was expected to have type record with attributes: "#),
            "actual error message was {err}"
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
        assert!(
            err.to_string().contains(r#"in attribute `manager` on `XYZCorp::Employee::"12UA45"`, type mismatch: value was expected to have type `XYZCorp::Employee`, but actually has type `Employee`: `Employee::"34FB87"`"#),
            "actual error message was {err}"
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

    /// Test that involves open entities
    #[test]
    #[should_panic(
        expected = "UnsupportedFeature(\"records and entities with additional attributes are not yet implemented\")"
    )]
    fn open_entities() {
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
                        },
                        "additionalAttributes": true
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
        assert_eq!(parsed.iter().count(), 1);

        // providing another attribute "foobar" should be OK
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
        let parsed = Entities::from_json_value(entitiesjson, Some(&schema))
            .expect("Should parse without error");
        assert_eq!(parsed.iter().count(), 1);
    }

    #[test]
    fn schema_sanity_check() {
        let src = "{ , .. }";
        assert_matches!(Schema::from_str(src), Err(super::SchemaError::Serde(_)));
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
        let src = r#"
            permit(principal, action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(t.principal_constraint(), TemplatePrincipalConstraint::Any);

        let src = r#"
            permit(principal == ?principal, action, resource);
        "#;
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

        let src = r#"
            permit(principal in ?principal, action, resource);
        "#;
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

        let src = r#"
            permit(principal is A, action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.principal_constraint(),
            TemplatePrincipalConstraint::Is(EntityTypeName::from_str("A").unwrap())
        );
        let src = r#"
            permit(principal is A in ?principal, action, resource);
        "#;
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
        let src = r#"
            permit(principal, action, resource);
        "#;
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
        let src = r#"
            permit(principal, action, resource);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(t.resource_constraint(), TemplateResourceConstraint::Any);

        let src = r#"
            permit(principal, action, resource == ?resource);
        "#;
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

        let src = r#"
            permit(principal, action, resource in ?resource);
        "#;
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

        let src = r#"
            permit(principal, action, resource is A);
        "#;
        let t = Template::parse(None, src).unwrap();
        assert_eq!(
            t.resource_constraint(),
            TemplateResourceConstraint::Is(EntityTypeName::from_str("A").unwrap())
        );
        let src = r#"
            permit(principal, action, resource is A in ?resource);
        "#;
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
        let r = Entities::from_json_value(json, None).err().unwrap();
        let expected_euid: cedar_policy_core::ast::EntityUID = r#"User::"alice""#.parse().unwrap();
        match r {
            EntitiesError::Duplicate(euid) => assert_eq!(euid, expected_euid),
            e => panic!("Wrong error. Expected `Duplicate`, got: {e:?}"),
        }
    }

    /// Test that schema-based parsing accepts unknowns in any position where any type is expected
    #[test]
    fn issue_418() {
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
        ))
        .expect("should be a valid schema");

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

        let parsed = Entities::from_json_value(entitiesjson.clone(), Some(&schema))
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
}
