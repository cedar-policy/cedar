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
// PANIC SAFETY: unit tests
#![allow(
    clippy::cognitive_complexity,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::unreachable
)]

mod demo_tests {
    use std::{
        collections::BTreeMap,
        iter::{empty, once},
    };

    use crate::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use crate::{est::Annotations, extensions::Extensions};
    use cool_asserts::assert_matches;
    use smol_str::ToSmolStr;

    use crate::validator::{
        cedar_schema::{self, err::NO_PR_HELP_MSG},
        json_schema::{self, EntityType, EntityTypeKind},
        schema::test::utils::collect_warnings,
        CedarSchemaError, RawName,
    };

    use itertools::Itertools;
    use miette::Diagnostic;

    #[test]
    fn no_applies_to() {
        let src = r#"
            action "Foo";
        "#;
        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::none()).unwrap();
        let foo = schema.0.get(&None).unwrap().actions.get("Foo").unwrap();
        assert_matches!(foo,
            json_schema::ActionType {
                applies_to : Some(json_schema::ApplySpec {
                    resource_types : resources,
                    principal_types : principals, ..
                }),
                ..
            } => assert!(resources.is_empty() && principals.is_empty())
        );
    }

    #[test]
    fn just_context() {
        let src = r#"
        action "Foo" appliesTo { context: {} };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::none())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `resource` declaration for `Foo`")
                    .exactly_one_underline("\"Foo\"")
                    .help(NO_PR_HELP_MSG)
                    .build(),
            );
        });
    }

    #[test]
    fn just_principal() {
        let src = r#"
        entity a;
        action "Foo" appliesTo { principal: a, context: {}  };
        "#;

        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::none())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `resource` declaration for `Foo`")
                    .exactly_one_underline("\"Foo\"")
                    .help(NO_PR_HELP_MSG)
                    .build(),
            );
        });
    }

    #[test]
    fn just_resource() {
        let src = r#"
        entity a;
        action "Foo" appliesTo { resource: a, context: {}  };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::none())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `principal` declaration for `Foo`")
                    .exactly_one_underline("\"Foo\"")
                    .help(NO_PR_HELP_MSG)
                    .build(),
            );
        });
    }

    #[test]
    fn resource_only() {
        let src = r#"
            entity a;
            action "Foo" appliesTo {
                resource : [a]
            };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `principal` declaration for `Foo`")
                    .exactly_one_underline("\"Foo\"")
                    .help(NO_PR_HELP_MSG)
                    .build(),
            );
        });
    }

    #[test]
    fn resources_only() {
        let src = r#"
            entity a;
            entity b;
            action "Foo" appliesTo {
                resource : [a, b]
            };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `principal` declaration for `Foo`")
                    .exactly_one_underline("\"Foo\"")
                    .help(NO_PR_HELP_MSG)
                    .build(),
            );
        });
    }

    #[test]
    fn principal_only() {
        let src = r#"
            entity a;
            action "Foo" appliesTo {
                principal: [a]
            };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `resource` declaration for `Foo`")
                    .exactly_one_underline("\"Foo\"")
                    .help(NO_PR_HELP_MSG)
                    .build(),
            );
        });
    }

    #[test]
    fn principals_only() {
        let src = r#"
            entity a;
            entity b;
            action "Foo" appliesTo {
                principal: [a, b]
            };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `resource` declaration for `Foo`")
                    .exactly_one_underline("\"Foo\"")
                    .help(NO_PR_HELP_MSG)
                    .build(),
            );
        });
    }

    #[test]
    fn empty_principal() {
        let src = r#"
            entity a;
            entity b;
            action Foo appliesTo {
                principal: [],
                resource: [a, b]
            };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: for action `Foo`, `principal` is `[]`, which is invalid")
                    .with_underlines_or_labels([("Foo", Some("for this action")), ("principal: []", Some("must not be `[]`"))])
                    .help(NO_PR_HELP_MSG)
                    .build(),
            );
        });
    }

    #[test]
    fn empty_resource() {
        let src = r#"
            entity a;
            entity b;
            action Foo appliesTo {
                principal: [a, b],
                resource: []
            };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: for action `Foo`, `resource` is `[]`, which is invalid")
                    .with_underlines_or_labels([("Foo", Some("for this action")), ("resource: []", Some("must not be `[]`"))])
                    .help(NO_PR_HELP_MSG)
                    .build(),
            );
        });
    }

    #[test]
    fn both_targets() {
        let src = r#"
            entity a;
            entity b;
            entity c;
            entity d;
            action "Foo" appliesTo {
                principal: [a, b],
                resource: [c, d]
            };
        "#;
        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let unqual = schema.0.get(&None).unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(&foo, json_schema::ActionType {
            applies_to: Some(json_schema::ApplySpec { resource_types, principal_types, .. }),
            ..
        } => {
            assert_matches!(principal_types.as_slice(), [a,b] => {
                assert_eq!(a, &"a".parse().unwrap());
                assert_eq!(b, &"b".parse().unwrap());
            });
            assert_matches!(resource_types.as_slice(), [c,d] =>  {
                assert_eq!(c, &"c".parse().unwrap());
                assert_eq!(d, &"d".parse().unwrap());
            });
        });
    }

    #[test]
    fn both_targets_flipped() {
        let src = r#"
            entity a;
            entity b;
            entity c;
            entity d;
            action "Foo" appliesTo {
                resource: [c, d],
                principal: [a, b]
            };
        "#;
        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let unqual = schema.0.get(&None).unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(foo, json_schema::ActionType {
            applies_to: Some(json_schema::ApplySpec { resource_types, principal_types, .. }),
            ..
        } => {
            assert_matches!(principal_types.as_slice(), [a,b] => {
                assert_eq!(a, &"a".parse().unwrap());
                assert_eq!(b, &"b".parse().unwrap());
            });
            assert_matches!(resource_types.as_slice(), [c,d] =>  {
                assert_eq!(c, &"c".parse().unwrap());
                assert_eq!(d, &"d".parse().unwrap());
            });
        });
    }

    #[test]
    fn duplicate_principal() {
        let src = r#"
            entity a;
            entity b;
            entity c;
            entity d;
            action "Foo" appliesTo {
                principal: [a, b],
                principal : [c]
            };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"error parsing schema: duplicate `principal` declaration in action `Foo`"#
            ).help(
                "Actions may only have a single principal declaration, but a principal declaration may specify a list of entity types like `principal: [X, Y, Z]`"
            ).exactly_two_underlines("principal: [a, b]", "principal : [c]").build());
        });
    }

    #[test]
    fn duplicate_resource() {
        let src = r#"
            entity a;
            entity b;
            entity c;
            entity d;
            action "Foo" appliesTo {
                resource: [a, b],
                resource: [c]
            };
        "#;
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Err(e) => {
            expect_err(src, &miette::Report::new(e), &ExpectedErrorMessageBuilder::error(
                r#"error parsing schema: duplicate `resource` declaration in action `Foo`"#
            ).help(
                "Actions may only have a single resource declaration, but a resource declaration may specify a list of entity types like `resource: [X, Y, Z]`"
            ).exactly_two_underlines("resource: [a, b]", "resource: [c]").build());
        });
    }

    #[test]
    fn empty_appliesto() {
        let action = json_schema::ActionType::<RawName> {
            attributes: None,
            applies_to: None,
            member_of: None,
            annotations: Annotations::new(),
            loc: None,
            #[cfg(feature = "extended-schema")]
            defn_loc: None,
        };
        let namespace =
            json_schema::NamespaceDefinition::new(empty(), once(("foo".to_smolstr(), action)));
        let fragment =
            json_schema::Fragment(BTreeMap::from([(Some("bar".parse().unwrap()), namespace)]));
        let as_src = fragment.to_cedarschema().unwrap();
        let expected = r#"action "foo";"#;
        assert!(as_src.contains(expected), "src was:\n`{as_src}`");
    }

    #[test]
    fn context_is_common_type() {
        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                r#"
        type empty = {};
        entity E;
        action "Foo" appliesTo {
            context: empty,
            principal: [E],
            resource: [E]
        };
    "#,
                Extensions::all_available(),
            )),
            Ok(_)
        );
        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                r#"
    type flag = { value: __cedar::Bool };
    action "Foo" appliesTo {
        context: flag,
        principal: [E],
        resource: [E]
    };
"#,
                Extensions::all_available(),
            )),
            Ok(_)
        );
        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                r#"
namespace Bar { type empty = {}; }
action "Foo" appliesTo {
    context: Bar::empty,
    principal: [E],
    resource: [E]
};
"#,
                Extensions::all_available(),
            )),
            Ok(_)
        );
        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                r#"
namespace Bar { type flag = { value: Bool }; }
namespace Baz {action "Foo" appliesTo {
    context: Bar::flag,
    principal: [E],
    resource: [E]
};}
"#,
                Extensions::all_available(),
            )),
            Ok(_)
        );
        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                r#"
        type authcontext = {
            ip: ipaddr,
            is_authenticated: Bool,
            timestamp: Long
        };
        entity Ticket {
          who: String,
          operation: Long,
          request: authcontext
        };
        action view appliesTo { context: authcontext, principal: [E], resource: [E] };
        action upload appliesTo { context: authcontext, principal: [E], resource: [E]};
"#,
                Extensions::all_available(),
            )),
            Ok(_)
        );
    }

    #[test]
    fn print_actions() {
        let namespace = json_schema::NamespaceDefinition::new(
            [(
                "a".parse().unwrap(),
                json_schema::StandardEntityType::<RawName> {
                    member_of_types: vec![],
                    shape: json_schema::AttributesOrContext::default(),
                    tags: None,
                }
                .into(),
            )],
            BTreeMap::from([(
                "j".to_smolstr(),
                json_schema::ActionType::<RawName> {
                    attributes: None,
                    applies_to: Some(json_schema::ApplySpec::<RawName> {
                        resource_types: vec![],
                        principal_types: vec!["a".parse().unwrap()],
                        context: json_schema::AttributesOrContext::default(),
                    }),
                    member_of: None,
                    annotations: Annotations::new(),
                    loc: None,
                    #[cfg(feature = "extended-schema")]
                    defn_loc: None,
                },
            )]),
        );
        let fragment = json_schema::Fragment(BTreeMap::from([(None, namespace)]));
        let src = fragment.to_cedarschema().unwrap();
        assert!(src.contains(r#"action "j";"#), "schema was: `{src}`")
    }

    #[test]
    fn fully_qualified_actions() {
        let (_, _) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace NS1 {entity PrincipalEntity  = {  };
        entity SystemEntity1  = {  };
        entity SystemEntity2 in [SystemEntity1] = {  };
        action "Group1" ;
        }namespace NS2 {entity SystemEntity1 in [NS1::SystemEntity2] = {  };
        action "Group1" in [NS1::Action::"Group1"];
        action "Action1" in [Action::"Group1"]appliesTo {  principal: [NS1::PrincipalEntity],
          resource: [NS2::SystemEntity1],
          context: {  }
        };
        }
        "#,
            Extensions::all_available(),
        )
        .expect("schema should parse");
    }

    #[test]
    fn action_eid_invalid_escape() {
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"namespace NS1 {entity PrincipalEntity  = {  };
        entity SystemEntity1  = {  };
        entity SystemEntity2 in [SystemEntity1] = {  };
        action "Group1" ;
        }namespace NS2 {entity SystemEntity1 in [NS1::SystemEntity2] = {  };
        action "Group1" in [NS1::Action::"Group1"];
        action "Action1" in [Action::"\6"]appliesTo {  principal: [NS1::PrincipalEntity],
          resource: [NS2::SystemEntity1],
          context: {  }
        };
        }
        "#,
            Extensions::all_available(),
        )), Err(err) => {
            assert_matches!(err, CedarSchemaError::Parsing(err) => {
                assert_matches!(err.errors(), cedar_schema::parser::CedarSchemaParseErrors::SyntaxError(errs) => {
                    assert!(errs.to_smolstr().contains("Invalid escape codes"));
                });
            });
        });
    }

    #[test]
    fn test_github() {
        let (fragment, warnings) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace GitHub {
            entity User in [UserGroup,Team];
            entity UserGroup in [UserGroup];
            entity Repository {
                readers: UserGroup,
                triagers: UserGroup,
                writers: UserGroup,
                maintainers: UserGroup,
                admins: UserGroup
            };
            entity Issue {
                repo: Repository,
                reporter: User
            };
            entity Org {
                members: UserGroup,
                owners: UserGroup,
                memberOfTypes: UserGroup
            };
        }"#,
            Extensions::all_available(),
        )
        .expect("Schema should parse");
        assert_eq!(warnings.collect::<Vec<_>>(), vec![]);
        let github = fragment
            .0
            .get(&Some("GitHub".parse().unwrap()))
            .expect("`Github` name space did not exist");
        // User
        assert_matches!(github
            .entity_types
            .get(&"User".parse().unwrap())
            .expect("No `User`"), EntityType { kind: EntityTypeKind::Standard(user), ..} => {
        assert_empty_record(user);
        assert_eq!(
            &user.member_of_types,
            &vec!["UserGroup".parse().unwrap(), "Team".parse().unwrap()]
        );});
        // UserGroup
        assert_matches!(github
            .entity_types
            .get(&"UserGroup".parse().unwrap())
            .expect("No `UserGroup`"), EntityType { kind: EntityTypeKind::Standard(usergroup), ..} => {
        assert_empty_record(usergroup);
        assert_eq!(
            &usergroup.member_of_types,
            &vec!["UserGroup".parse().unwrap()]
        );});
        // Repository
        assert_matches!(github
            .entity_types
            .get(&"Repository".parse().unwrap())
            .expect("No `Repository`"), EntityType {kind: EntityTypeKind::Standard(repo),  ..} => {
        assert!(repo.member_of_types.is_empty());
        let groups = ["readers", "writers", "triagers", "admins", "maintainers"];
        for group in groups {
            assert_matches!(&repo.shape, json_schema::AttributesOrContext(json_schema::Type::Type { ty: json_schema::TypeVariant::Record(json_schema::RecordType {
                attributes,
                additional_attributes: false,
            }), loc: Some(_) }) => {
                let expected =
                    json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                        type_name: "UserGroup".parse().unwrap(),
                    }, loc: None};
                let attribute = attributes.get(group).unwrap_or_else(|| panic!("No attribute `{group}`"));
                assert_has_type(attribute, &expected);
            });
        }});
        assert_matches!(github
            .entity_types
            .get(&"Issue".parse().unwrap())
            .expect("No `Issue`"), EntityType {kind: EntityTypeKind::Standard(issue), .. } => {
        assert!(issue.member_of_types.is_empty());
        assert_matches!(&issue.shape, json_schema::AttributesOrContext(json_schema::Type::Type { ty: json_schema::TypeVariant::Record(json_schema::RecordType {
            attributes,
            additional_attributes: false,
        }), loc: Some(_) }) => {
            let attribute = attributes.get("repo").expect("No `repo`");
            assert_has_type(
                attribute,
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "Repository".parse().unwrap(),
                }, loc: None },
            );
            let attribute = attributes.get("reporter").expect("No `repo`");
            assert_has_type(
                attribute,
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "User".parse().unwrap(),
                }, loc: None },
            );
        });});
        assert_matches!(github
            .entity_types
            .get(&"Org".parse().unwrap())
            .expect("No `Org`"), EntityType { kind: EntityTypeKind::Standard(org), .. } => {
        assert!(org.member_of_types.is_empty());
        let groups = ["members", "owners", "memberOfTypes"];
        for group in groups {
            assert_matches!(&org.shape, json_schema::AttributesOrContext(json_schema::Type::Type { ty: json_schema::TypeVariant::Record(json_schema::RecordType {
                attributes,
                additional_attributes: false,
            }), loc: Some(_) }) => {
                let expected = json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "UserGroup".parse().unwrap(),
                }, loc: None };
                let attribute = attributes.get(group).unwrap_or_else(|| panic!("No attribute `{group}`"));
                assert_has_type(attribute, &expected);
            });
        }});
    }

    #[track_caller]
    fn assert_has_type<N: std::fmt::Debug + PartialEq>(
        e: &json_schema::TypeOfAttribute<N>,
        expected: &json_schema::Type<N>,
    ) {
        assert!(e.required);
        assert_eq!(&e.ty, expected);
    }

    #[track_caller]
    fn assert_empty_record<N: std::fmt::Debug>(etyp: &json_schema::StandardEntityType<N>) {
        assert!(etyp.shape.is_empty_record());
    }

    #[test]
    fn test_doc_cloud() {
        let (fragment, warnings) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace DocCloud {
            entity User in [Group] {
                personalGroup: Group,
                blocked: Set<User>
            };
            entity Group in [DocumentShare] {
                owner: User
            };
            entity Document {
                owner: User,
                isPrivate: Bool,
                publicAccess: String,
                viewACL: DocumentShare,
                modifyACL: DocumentShare,
                manageACL: DocumentShare
            };
            entity DocumentShare;
            entity Public in [DocumentShare];
            entity Drive;
        }"#,
            Extensions::all_available(),
        )
        .expect("failed to parse");
        assert_eq!(warnings.collect::<Vec<_>>(), vec![]);
        let doccloud = fragment
            .0
            .get(&Some("DocCloud".parse().unwrap()))
            .expect("No `DocCloud` namespace");
        assert_matches!(doccloud
            .entity_types
            .get(&"User".parse().unwrap())
            .expect("No `User`"), EntityType {kind: EntityTypeKind::Standard(user), ..} => {
        assert_eq!(&user.member_of_types, &vec!["Group".parse().unwrap()]);
        assert_matches!(&user.shape, json_schema::AttributesOrContext(json_schema::Type::Type { ty: json_schema::TypeVariant::Record(json_schema::RecordType {
            attributes,
            additional_attributes: false,
        }), loc: Some(_) }) => {
            assert_has_type(
                attributes.get("personalGroup").unwrap(),
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "Group".parse().unwrap(),
                }, loc: None }, // we do expect a `loc`, but `assert_has_type()` will ignore the mismatch in presence of `loc`. We have separate tests for the correctness of `loc`s coming from the Cedar schema syntax in a test module called `preserves_source_locations`.
            );
            assert_has_type(
                attributes.get("blocked").unwrap(),
                &json_schema::Type::Type { ty: json_schema::TypeVariant::Set {
                    element: Box::new(json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                        type_name: "User".parse().unwrap(),
                    }, loc: None }), // we do expect a `loc`, but `assert_has_type()` will ignore the mismatch in presence of `loc`. We have separate tests for the correctness of `loc`s coming from the Cedar schema syntax in a test module called `preserves_source_locations`.
                }, loc: None },
            );
        });});
        assert_matches!(doccloud
            .entity_types
            .get(&"Group".parse().unwrap())
            .expect("No `Group`"), EntityType { kind: EntityTypeKind::Standard(group), .. } => {
        assert_eq!(
            &group.member_of_types,
            &vec!["DocumentShare".parse().unwrap()]
        );
        assert_matches!(&group.shape, json_schema::AttributesOrContext(json_schema::Type::Type { ty: json_schema::TypeVariant::Record(json_schema::RecordType {
            attributes,
            additional_attributes: false,
        }), loc: Some(_) }) => {
            assert_has_type(
                attributes.get("owner").unwrap(),
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "User".parse().unwrap(),
                }, loc: None },
            );
        });});
        assert_matches!(doccloud
            .entity_types
            .get(&"Document".parse().unwrap())
            .expect("No `Group`"), EntityType { kind: EntityTypeKind::Standard(document), ..} => {
        assert!(document.member_of_types.is_empty());
        assert_matches!(&document.shape, json_schema::AttributesOrContext(json_schema::Type::Type { ty: json_schema::TypeVariant::Record(json_schema::RecordType {
            attributes,
            additional_attributes: false,
        }), loc: Some(_) }) => {
            assert_has_type(
                attributes.get("owner").unwrap(),
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "User".parse().unwrap(),
                }, loc: None },
            );
            assert_has_type(
                attributes.get("isPrivate").unwrap(),
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "Bool".parse().unwrap(),
                }, loc: None },
            );
            assert_has_type(
                attributes.get("publicAccess").unwrap(),
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "String".parse().unwrap(),
                }, loc: None },
            );
            assert_has_type(
                attributes.get("viewACL").unwrap(),
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "DocumentShare".parse().unwrap(),
                }, loc: None },
            );
            assert_has_type(
                attributes.get("modifyACL").unwrap(),
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "DocumentShare".parse().unwrap(),
                }, loc: None },
            );
            assert_has_type(
                attributes.get("manageACL").unwrap(),
                &json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon {
                    type_name: "DocumentShare".parse().unwrap(),
                }, loc: None },
            );
        });});
        assert_matches!(doccloud
            .entity_types
            .get(&"DocumentShare".parse().unwrap())
            .expect("No `DocumentShare`"), EntityType { kind: EntityTypeKind::Standard(document_share), ..} => {
        assert!(document_share.member_of_types.is_empty());
        assert_empty_record(document_share);
            });

        assert_matches!(doccloud
                .entity_types
                .get(&"Public".parse().unwrap())
                .expect("No `Public`"), EntityType { kind: EntityTypeKind::Standard(public), ..} => {
            assert_eq!(
                &public.member_of_types,
                &vec!["DocumentShare".parse().unwrap()]
            );
            assert_empty_record(public);
        });

        assert_matches!(doccloud
            .entity_types
            .get(&"Drive".parse().unwrap())
            .expect("No `Drive`"), EntityType { kind: EntityTypeKind::Standard(drive), ..} => {
        assert!(drive.member_of_types.is_empty());
        assert_empty_record(drive);
            });
    }

    #[test]
    fn simple_action() {
        let src = r#"
        entity A;
        entity B;
        action Foo appliesTo { principal : A, resource : B  };
        "#;
        let (_, warnings) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        assert_eq!(warnings.collect::<Vec<_>>(), vec![]);
    }

    #[test]
    fn tinytodo() {
        let src = r#"
        namespace TinyTodo {
        entity Application {};
        entity User in [Team, Application] {
            location : String,
            joblevel : Long
        };
        entity Team in [Team, Application];
        entity List in [Application] {
            owner : User,
            name : String,
            readers : Team,
            editors : Team,
            Tasks : Set<{ name : String, id : Long, state : String }>
        };

        action CreateList appliesTo {
            principal : User,
            resource : Application
        };

        action GetList appliesTo {
            principal : User,
            resource : Application
        };

        action UpdateList appliesTo {
            principal : User,
            resource : List
        };

        action DeleteList appliesTo {
            principal : User,
            resource : List
        };

        action GetLists appliesTo {
            principal : User,
            resource : Application
        };

        action CreateTask appliesTo {
            principal : User,
            resource : List
        };

        action UpdateTask appliesTo {
            principal : User,
            resource : List
        };

        action DeleteTask appliesTo {
            principal : User,
            resource : List
        };

        action EditShare appliesTo {
            principal : User,
            resource : List
        };
        }
        "#;

        let (_, warnings) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        assert_eq!(warnings.collect::<Vec<_>>(), vec![]);
    }

    #[test]
    fn simple_cross() {
        let src = r#"
        namespace AWS {
            type Tag = {
                key: String,
                value: String
            };
        }

        namespace Service {
            entity Resource {
                tag: AWS::Tag
            };
        }
        "#;
        let (fragment, warnings) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        assert_eq!(warnings.collect::<Vec<_>>(), vec![]);
        let service = fragment.0.get(&Some("Service".parse().unwrap())).unwrap();
        assert_matches!(service
            .entity_types
            .get(&"Resource".parse().unwrap())
            .unwrap(), EntityType { kind: EntityTypeKind::Standard(resource), ..} => {
        assert_matches!(&resource.shape, json_schema::AttributesOrContext(json_schema::Type::Type { ty: json_schema::TypeVariant::Record(json_schema::RecordType {
            attributes,
            additional_attributes: false,
        }), ..}) => {
            assert_matches!(attributes.get("tag"), Some(json_schema::TypeOfAttribute { ty, required: true, .. }) => {
                assert_matches!(&ty, json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon { type_name }, loc: Some(loc) } => {
                    assert_eq!(type_name, &"AWS::Tag".parse().unwrap());
                    assert_matches!(loc.snippet(), Some("AWS::Tag"));
                });
            });
        });});
    }

    #[test]
    fn expected_tokens() {
        #[track_caller]
        fn assert_labeled_span(src: &str, label: impl Into<String>) {
            assert_matches!(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).map(|(s, _)| s), Err(e) => {
                let actual_label = e.labels().and_then(|l| {
                    l.exactly_one()
                        .ok()
                        .expect("Assumed that there would be exactly one label if labels are present")
                        .label()
                        .map(|l| l.to_string())
                });
                assert_eq!(Some(label.into()), actual_label, "Did not see expected labeled span.");
            });
        }

        assert_labeled_span("namespace", "expected identifier");
        assert_labeled_span("type", "expected identifier");
        assert_labeled_span("entity", "expected identifier");
        assert_labeled_span("action", "expected identifier or string literal");
        assert_labeled_span("type t =", "expected `{`, identifier, or `Set`");
        assert_labeled_span(
            "entity User {",
            "expected `@`, `}`, identifier, or string literal",
        );
        assert_labeled_span("entity User { name:", "expected `{`, identifier, or `Set`");
    }
}

mod parser_tests {
    use crate::validator::cedar_schema::{
        ast::{Annotated, Declaration, EntityDecl, EnumEntityDecl, Namespace},
        parser::parse_schema,
    };
    use cool_asserts::assert_matches;

    #[test]
    fn mixed_decls() {
        let res = parse_schema(
            r#"
        entity A;
        namespace Foo {}
        type B = A;
        "#,
        );
        assert_matches!(res, Ok(_));
    }

    #[test]
    fn entity_decl_basic() {
        let res = parse_schema(
            r#"
    entity A;
        "#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    entity "A";
    "#,
        );
        assert_matches!(res, Err(_));
        let res = parse_schema(
            r#"
    entity A in B;
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    entity A in [B];
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    entity A in [B, C];
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    entity A in [B, C];
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    entity A in [B, C] {};
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    entity A in [B, C] = {};
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    entity A in [B, C] = {foo: String};
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    entity A in [B, C] = {foo: String,};
"#,
        );
        assert_matches!(res, Ok(_));
    }

    #[test]
    fn action_decl_basic() {
        let res = parse_schema(
            r#"
    action A;
        "#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    action "A";
    "#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    action A in B;
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    action A in [B];
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    action A in [B, C];
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    action A in [B, C];
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo {};
"#,
        );
        assert_matches!(res, Err(_));
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { context: {}};
"#,
        );
        assert_matches!(res, Ok(_)); // becomes an error in later processing
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: []};
"#,
        );
        assert_matches!(res, Ok(_)); // becomes an error in later processing
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: X, resource: [Y]};
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: X, resource: [Y,]};
"#,
        );
        assert_matches!(res, Err(_));
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: X, resource: [Y,Z]} attributes {};
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: X, resource: [Y,Z]} = attributes {};
"#,
        );
        assert_matches!(res, Err(_));
    }

    #[test]
    fn common_type_decl_basic() {
        let res = parse_schema(
            r#"
    type A = B;
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    type "A" = B;
"#,
        );
        assert_matches!(res, Err(_));
        let res = parse_schema(
            r#"
    type A = "B";
"#,
        );
        assert_matches!(res, Err(_));
        let res = parse_schema(
            r#"
    type A = B::C;
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    type A = Bool;
    type B = __cedar::Bool;
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    type A = Long;
    type B = __cedar::Long;
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    type A = String;
    type B = __cedar::String;
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    type A = ipaddr;
    type B = __cedar::ipaddr;
"#,
        );
        assert_matches!(res, Ok(_));
        let res = parse_schema(
            r#"
    type A = decimal;
    type B = __cedar::decimal;
"#,
        );
        assert_matches!(res, Ok(_));
    }

    #[test]
    fn enumerated_entity_types() {
        let res = parse_schema(
            r#"
        entity Application enum [ "TinyTodo" ];
        entity User in [ Application ];
        "#,
        );
        assert_matches!(res, Ok(ns) => {
            assert_matches!(&ns, [Annotated {data: Namespace { decls, ..}, ..}, ..] => {
                assert_matches!(decls, [Annotated { data, .. }] => {
                    assert_matches!(&data.node, Declaration::Entity(EntityDecl::Enum(EnumEntityDecl { choices, ..})) => {
                        assert_eq!(choices.clone().map(|n| n.node), nonempty::NonEmpty::singleton("TinyTodo".into()));
                    });
                });
            });
        });
        let res = parse_schema(
            r#"
        entity Application enum [ "TinyTodo", "GitHub", "DocumentCloud" ];
        entity User in [ Application ];
        "#,
        );
        assert_matches!(res, Ok(ns) => {
            assert_matches!(&ns, [Annotated {data: Namespace { decls, ..}, ..}, ..] => {
                assert_matches!(decls, [Annotated { data, .. }] => {
                    assert_matches!(&data.node, Declaration::Entity(EntityDecl::Enum(EnumEntityDecl { choices, ..})) => {
                        assert_eq!(choices.clone().map(|n| n.node), nonempty::nonempty!["TinyTodo".into(), "GitHub".into(), "DocumentCloud".into()]);
                    });
                });
            });
        });
        let res = parse_schema(
            r#"
        entity enum enum [ "enum" ];
        "#,
        );
        assert_matches!(res, Ok(ns) => {
            assert_matches!(&ns, [Annotated {data: Namespace { decls, ..}, ..}] => {
                assert_matches!(decls, [Annotated { data, .. }] => {
                    assert_matches!(&data.node, Declaration::Entity(EntityDecl::Enum(EnumEntityDecl { choices, ..})) => {
                        assert_eq!(choices.clone().map(|n| n.node), nonempty::NonEmpty::singleton("enum".into()));
                    });
                });
            });
        });

        let res = parse_schema(
            r#"
        entity Application enum [ ];
        entity User in [ Application ];
        "#,
        );
        // Maybe we want a better error message here
        assert_matches!(res, Err(errs) => {
            assert_eq!(errs.to_string(), "unexpected token `]`");
        });
    }
}

mod translator_tests {
    use crate::ast as cedar_ast;
    use crate::extensions::Extensions;
    use crate::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use crate::FromNormalizedStr;
    use cool_asserts::assert_matches;

    use crate::validator::json_schema::{EntityType, EntityTypeKind};
    use crate::validator::{
        cedar_schema::{
            err::ToJsonSchemaError, parser::parse_schema,
            to_json_schema::cedar_schema_to_json_schema,
        },
        json_schema,
        schema::test::utils::collect_warnings,
        types::{EntityLUB, EntityRecordKind, Primitive, Type},
        ValidatorSchema,
    };

    use super::SPECIAL_IDS;

    // We allow translating schemas that violate RFC 52 to `json_schema::Fragment`.
    // The violations are reported during further translation to `ValidatorSchema`
    #[test]
    fn use_reserved_namespace() {
        let schema = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
          namespace __cedar {}
        "#,
            Extensions::all_available(),
        ));
        assert_matches!(schema, Err(_));

        let schema = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
          namespace __cedar::Foo {}
        "#,
            Extensions::all_available(),
        ));
        assert_matches!(schema, Err(_));
    }

    /// Test that duplicate namespaces are not allowed
    #[test]
    fn duplicate_namespace() {
        let schema = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
          namespace A {}
          namespace A {}
        "#,
            Extensions::all_available(),
        ));
        assert_matches!(schema, Err(_));
    }

    /// Test that duplicate action names are not allowed
    #[test]
    fn duplicate_actions() {
        let schema = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
          action A;
          action A appliesTo { context: {}};
        "#,
            Extensions::all_available(),
        ));
        assert_matches!(schema, Err(_));

        let schema = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
          action A;
          action "A";
        "#,
            Extensions::all_available(),
        ));
        assert_matches!(schema, Err(_));

        let schema = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
            namespace Foo {
          action A;
          action "A";
            };
        "#,
            Extensions::all_available(),
        ));
        assert_matches!(schema, Err(_));

        let schema = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
          namespace X { action A; }
          action A;
        "#,
            Extensions::all_available(),
        ));
        assert_matches!(schema, Ok(_));
    }

    /// Test that duplicate entity type names are not allowed
    #[test]
    fn duplicate_entity_types() {
        let schema = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
          entity A;
          entity A {};
        "#,
            Extensions::all_available(),
        ));
        assert_matches!(schema, Err(_));
        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                r#"
          entity A,A {};
        "#,
                Extensions::all_available(),
            )),
            Err(_)
        );
        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                r#"
          namespace X { entity A; }
          entity A {};
        "#,
                Extensions::all_available(),
            )),
            Ok(_)
        );
    }

    /// Test that duplicate common type names are not allowed
    #[test]
    fn duplicate_common_types() {
        let schema = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
          type A = Bool;
          type A = Long;
        "#,
            Extensions::all_available(),
        ));
        assert_matches!(schema, Err(_));
        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                r#"
          namespace X { type A = Bool; }
          type A = Long;
        "#,
                Extensions::all_available(),
            )),
            Ok(_)
        );
    }

    #[test]
    fn type_name_resolution_basic() {
        let (schema, _) = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"
        namespace Demo {
            entity Host {
              ip: ipaddr,
              bandwidth: decimal,
            };
            entity String {
              groups: Set<__cedar::String>,
            };
            type ipaddr = {
              repr: String,
              isV4: Bool,
            };
          }
        "#,
            Extensions::all_available(),
        ))
        .expect("should be a valid Cedar schema");
        let validator_schema: ValidatorSchema =
            schema.try_into().expect("should be a valid schema");
        for ety in validator_schema.entity_types() {
            match ety.name().to_string().as_ref() {
                "Demo::Host" => {
                    for (attr_name, attr) in ety.attributes().iter() {
                        match attr_name.as_ref() {
                            "ip" => assert_matches!(
                                &attr.attr_type,
                                Type::EntityOrRecord(EntityRecordKind::Record { .. })
                            ),
                            "bandwidth" => assert_matches!(
                                &attr.attr_type,
                                Type::ExtensionType { name } => {
                                    assert_eq!(name, &crate::ast::Name::from_normalized_str("decimal").unwrap());
                                }
                            ),
                            _ => panic!("unexpected attr: {attr_name}"),
                        }
                    }
                }
                "Demo::String" => {
                    for (attr_name, attr) in ety.attributes().iter() {
                        match attr_name.as_ref() {
                            "groups" => assert_matches!(
                                &attr.attr_type,
                                Type::Set { element_type: Some(t) } => {
                                    assert_eq!(**t, Type::Primitive { primitive_type: Primitive::String });
                                }
                            ),
                            _ => panic!("unexpected attr: {attr_name}"),
                        }
                    }
                }
                name => panic!("unexpected entity type: {name}"),
            }
        }
    }

    #[test]
    fn type_name_cross_namespace() {
        let (schema, _) = collect_warnings(json_schema::Fragment::from_cedarschema_str(
            r#"namespace A {
                entity B in [X::Y, A::C];
                entity C;
            }
            namespace X {
                entity Y;
            }
            "#,
            Extensions::all_available(),
        ))
        .unwrap();
        let validator_schema: ValidatorSchema =
            schema.try_into().expect("should be a valid schema");
        for et in validator_schema.entity_types() {
            if et.name().to_string() == "A::C" || et.name().to_string() == "X::Y" {
                assert!(et.descendants.contains(&cedar_ast::EntityType::from(
                    crate::ast::Name::from_normalized_str("A::B").unwrap()
                )));
            } else {
                assert!(et.descendants.is_empty());
            }
        }
    }

    #[test]
    fn type_name_resolution_empty_namespace() {
        let src = r#"
          type id = {
            group: String,
            name: String,
          };

          type email_address = {
            id: String,
            domain: String,
          };

          namespace Demo {
            entity User {
              name: id,
              email: email_address,
            };
            entity email_address {
              where: String,
            };
            // type id = String; // this would create another shadowing error, common shadowing common
          }"#;
        let (frag, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let demo = frag.0.get(&Some("Demo".parse().unwrap())).unwrap();
        assert_matches!(demo.entity_types.get(&"User".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(user), ..} => {
        assert_matches!(&user.shape, json_schema::AttributesOrContext(json_schema::Type::Type{ ty: json_schema::TypeVariant::Record(json_schema::RecordType {
            attributes,
            additional_attributes: false,
        }), ..}) => {
            assert_matches!(attributes.get("name"), Some(json_schema::TypeOfAttribute { ty, required: true, .. }) => {
                assert_matches!(ty, json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon { type_name }, loc: Some(_) } => {
                    assert_eq!(&type_name.to_string(), "id");
                });
            });
            assert_matches!(attributes.get("email"), Some(json_schema::TypeOfAttribute { ty, required: true, .. }) => {
                assert_matches!(ty, json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon { type_name }, loc: Some(_) } => {
                    assert_eq!(&type_name.to_string(), "email_address");
                });
            });
        });});
        assert_matches!(ValidatorSchema::try_from(frag), Err(e) => {
            expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("definition of `Demo::email_address` illegally shadows the existing definition of `email_address`")
                    .help("try renaming one of the definitions, or moving `email_address` to a different namespace")
                    .exactly_one_underline("entity email_address {\n              where: String,\n            };")
                    .build(),
            );
        });
    }

    #[test]
    fn type_name_resolution_cross_namespace() {
        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace A {
                entity B in [A::C] = {
                    foo?: X::Y,
                };
                entity C;
            }
            namespace X {
                type Y = Bool;
                entity Y;
            }
            "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema =
            schema.try_into().expect("should be a valid schema");
        let et = validator_schema
            .get_entity_type(&cedar_ast::EntityType::from(
                crate::ast::Name::from_normalized_str("A::B").unwrap(),
            ))
            .unwrap();
        let attr = et.attr("foo").unwrap();
        assert_matches!(
            &attr.attr_type,
            Type::Primitive {
                primitive_type: Primitive::Bool
            },
        );

        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace A {
                entity B in [A::C] = {
                    foo?: X::Y,
                };
                entity C;
            }
            namespace X {
                type Y = X::Z;
                entity Z;
            }
            "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_eq!(
            validator_schema
                .get_entity_type(&"A::B".parse().unwrap())
                .unwrap()
                .attr("foo")
                .unwrap()
                .attr_type,
            Type::EntityOrRecord(EntityRecordKind::Entity(EntityLUB::single_entity(
                "X::Z".parse().unwrap()
            )))
        );
    }

    #[test]
    fn entity_named_namespace() {
        let src = r#"
        entity namespace = {};
        entity Foo in [namespace] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {
        assert_eq!(foo.member_of_types, vec!["namespace".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_in() {
        // This fails because `in` is reserved
        let src = r#"
        entity in = {};
        entity Foo in [in] = {};
        "#;

        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                src,
                Extensions::all_available()
            )),
            Err(_)
        );
    }

    #[test]
    fn entity_named_set() {
        let src = r#"
        entity Set = {};
        entity Foo in [Set] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {
        assert_eq!(foo.member_of_types, vec!["Set".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_applies_to() {
        let src = r#"
        entity appliesTo = {};
        entity Foo in [appliesTo] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {
        assert_eq!(foo.member_of_types, vec!["appliesTo".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_principal() {
        let src = r#"
        entity principal = {};
        entity Foo in [principal ] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {
        assert_eq!(foo.member_of_types, vec!["principal".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_resource() {
        let src = r#"
        entity resource= {};
        entity Foo in [resource] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {
        assert_eq!(foo.member_of_types, vec!["resource".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_action() {
        let src = r#"
        entity action= {};
        entity Foo in [action] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {
        assert_eq!(foo.member_of_types, vec!["action".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_context() {
        let src = r#"
        entity context= {};
        entity Foo in [context] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {
            assert_eq!(foo.member_of_types, vec!["context".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_attributes() {
        let src = r#"
        entity attributes= {};
        entity Foo in [attributes] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {
            assert_eq!(foo.member_of_types, vec!["attributes".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_bool() {
        let src = r#"
        entity Bool= {};
        entity Foo in [Bool] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {
            assert_eq!(foo.member_of_types, vec!["Bool".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_long() {
        let src = r#"
        entity Long= {};
        entity Foo in [Long] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {        assert_eq!(foo.member_of_types, vec!["Long".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_string() {
        let src = r#"
        entity String= {};
        entity Foo in [String] = {};
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Foo".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(foo), ..} => {        assert_eq!(foo.member_of_types, vec!["String".parse().unwrap()]);
        });
    }

    #[test]
    fn entity_named_if() {
        let src = r#"
        entity if = {};
        entity Foo in [if] = {};
        "#;

        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                src,
                Extensions::all_available()
            )),
            Err(_)
        );
    }

    #[test]
    fn entity_named_like() {
        let src = r#"
        entity like = {};
        entity Foo in [like] = {};
        "#;

        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                src,
                Extensions::all_available()
            )),
            Err(_)
        );
    }

    #[test]
    fn entity_named_true() {
        let src = r#"
        entity true = {};
        entity Foo in [true] = {};
        "#;

        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                src,
                Extensions::all_available()
            )),
            Err(_)
        );
    }

    #[test]
    fn entity_named_false() {
        let src = r#"
        entity false = {};
        entity Foo in [false] = {};
        "#;

        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                src,
                Extensions::all_available()
            )),
            Err(_)
        );
    }

    #[test]
    fn entity_named_has() {
        let src = r#"
        entity has = {};
        entity Foo in [has] = {};
        "#;

        assert_matches!(
            collect_warnings(json_schema::Fragment::from_cedarschema_str(
                src,
                Extensions::all_available()
            )),
            Err(_)
        );
    }

    #[test]
    fn multiple_principal_decls() {
        let schema = json_schema::Fragment::from_cedarschema_str(
            r#"
        entity foo;
        action a appliesTo { principal: A, principal: A };
        "#,
            Extensions::all_available(),
        );
        assert_matches!(collect_warnings(schema), Err(_));

        let schema = json_schema::Fragment::from_cedarschema_str(
            r#"
        entity foo;
        action a appliesTo { principal: A, resource: B, principal: A };
        "#,
            Extensions::all_available(),
        );
        assert_matches!(collect_warnings(schema), Err(_));
    }

    #[test]
    fn multiple_resource_decls() {
        let schema = json_schema::Fragment::from_cedarschema_str(
            r#"
        entity foo;
        action a appliesTo { resource: A, resource: A };
        "#,
            Extensions::all_available(),
        );
        assert_matches!(collect_warnings(schema), Err(_));

        let schema = json_schema::Fragment::from_cedarschema_str(
            r#"
        entity foo;
        action a appliesTo { resource: A, principal: B, resource: A };
        "#,
            Extensions::all_available(),
        );
        assert_matches!(collect_warnings(schema), Err(_));
    }

    #[test]
    fn multiple_context_decls() {
        let schema = json_schema::Fragment::from_cedarschema_str(
            r#"
        entity foo;
        action a appliesTo { context: A, context: A };
        "#,
            Extensions::all_available(),
        );
        assert_matches!(collect_warnings(schema), Err(_));

        let schema = json_schema::Fragment::from_cedarschema_str(
            r#"
        entity foo;
        action a appliesTo { principal: C, context: A, context: A };
        "#,
            Extensions::all_available(),
        );
        assert_matches!(collect_warnings(schema), Err(_));

        let schema = json_schema::Fragment::from_cedarschema_str(
            r#"
        entity foo;
        action a appliesTo { resource: C, context: A, context: A };
        "#,
            Extensions::all_available(),
        );
        assert_matches!(collect_warnings(schema), Err(_));
    }

    #[test]
    fn reserved_namespace() {
        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"namespace __cedar {
                entity foo;
            }
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(_));

        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"namespace __cedar::A {
                entity foo;
            }
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(_));

        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"
                entity __cedar;
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(_));
    }

    #[test]
    fn reserved_json_schema_keyword_empty_namespace() {
        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"
               type Entity = Long;
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(errs) if matches!(errs.iter().next().unwrap(), ToJsonSchemaError::ReservedSchemaKeyword(_)));

        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"
               type Extension = Long;
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(errs) if matches!(errs.iter().next().unwrap(), ToJsonSchemaError::ReservedSchemaKeyword(_)));

        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"
               type Set = Long;
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(errs) if matches!(errs.iter().next().unwrap(), ToJsonSchemaError::ReservedSchemaKeyword(_)));

        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"
               type Record = Long;
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(errs) if matches!(errs.iter().next().unwrap(), ToJsonSchemaError::ReservedSchemaKeyword(_)));
    }

    #[test]
    fn reserved_json_schema_keyword_nonempty_namespace() {
        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"
                namespace NS {
               type Entity = Long;
            }
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(errs) if matches!(errs.iter().next().unwrap(), ToJsonSchemaError::ReservedSchemaKeyword(_)));

        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"
                namespace NS {
               type Extension = Long;
            }
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(errs) if matches!(errs.iter().next().unwrap(), ToJsonSchemaError::ReservedSchemaKeyword(_)));

        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"
                namespace NS {
               type Set = Long;
            }
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(errs) if matches!(errs.iter().next().unwrap(), ToJsonSchemaError::ReservedSchemaKeyword(_)));

        let schema = cedar_schema_to_json_schema(
            parse_schema(
                r#"
                namespace NS {
               type Record = Long;
            }
        "#,
            )
            .unwrap(),
            Extensions::none(),
        )
        .map(|_| ());
        assert_matches!(schema, Err(errs) if matches!(errs.iter().next().unwrap(), ToJsonSchemaError::ReservedSchemaKeyword(_)));
    }

    #[track_caller]
    fn test_translation(src: &str, json_value: &serde_json::Value) {
        let (schema, _) = cedar_schema_to_json_schema(
            parse_schema(src).expect("should parse Cedar schema"),
            Extensions::none(),
        )
        .expect("should translate to JSON schema");
        assert_eq!(&serde_json::to_value(schema).unwrap(), json_value);
    }

    #[test]
    fn any_id() {
        for id in SPECIAL_IDS {
            test_translation(
                &format!("@{id} entity User {{}};"),
                &serde_json::json!({
                    "": {
                        "entityTypes": {
                            "User": {
                                "annotations": {
                                    id: "",
                                }
                            }
                        },
                        "actions": {},
                    }
                }),
            )
        }
    }

    #[test]
    fn annotations() {
        // namespace annotations
        test_translation(
            r#"
            @a1
            @a2("")
            @a3("foo")
            namespace N {
              entity E;
            }
            "#,
            &serde_json::json!({
                "N": {
                    "entityTypes": {
                        "E": {}
                    },
                    "actions": {},
                    "annotations": {
                        "a1": "",
                        "a2": "",
                        "a3": "foo",
                    }
                }
            }),
        );

        // common type annotations
        test_translation(
            r#"
            @comment("A->B")
            type A = B;
            @comment("B->A")
            type B = A;
            "#,
            &serde_json::json!({
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                       "A": {
                        "type": "EntityOrCommon",
                        "name": "B",
                        "annotations": {
                            "comment": "A->B",
                        }
                       },
                       "B": {
                        "type": "EntityOrCommon",
                        "name": "A",
                        "annotations": {
                            "comment": "B->A",
                        }
                       }
                    }
                }
            }),
        );

        // entity type annotations
        test_translation(
            r#"
            @a1
            @a2("")
            @a3("foo")
            namespace N {
              @ae1("🌕")
              @ae2("moon")
              entity Moon;
            }
            @ae("🌎")
            entity Earth;
            "#,
            &serde_json::json!({
                "": {
                    "entityTypes": {
                        "Earth": {
                            "annotations": {
                                "ae": "🌎",
                            }
                        }
                    },
                    "actions": {},
                },
                "N": {
                    "entityTypes": {
                        "Moon": {
                            "annotations": {
                                "ae1": "🌕",
                                "ae2": "moon",
                            }
                        }
                    },
                    "actions": {},
                    "annotations": {
                        "a1": "",
                        "a2": "",
                        "a3": "foo",
                    }
                }
            }),
        );
        test_translation(
            r#"
            @ae("🍎🍏")
            entity Apple1, Apple2;
            "#,
            &serde_json::json!({
                "": {
                    "entityTypes": {
                        "Apple1": {
                            "annotations": {
                                "ae": "🍎🍏",
                            }
                        },
                        "Apple2": {
                            "annotations": {
                                "ae": "🍎🍏",
                            }
                        }
                    },
                    "actions": {},
                }
            }),
        );

        // action annotations
        test_translation(
            r#"
            @a1
            @a2("")
            @a3("foo")
            namespace N {
              @ae1("🌕")
              @ae2("moon")
              entity Moon;
            }
            @a("🌌")
            action "🚀","🛸" appliesTo {
                principal: [Astronaut, ET],
                resource: Earth,
            };
            "#,
            &serde_json::json!({
                "": {
                    "entityTypes": {},
                    "actions": {
                        "🚀": {
                            "annotations": {
                                "a": "🌌",
                            },
                            "appliesTo": {
                                "principalTypes": ["Astronaut", "ET"],
                                "resourceTypes": ["Earth"],
                            }
                        },
                        "🛸": {
                            "annotations": {
                                "a": "🌌",
                            },
                            "appliesTo": {
                                "principalTypes": ["Astronaut", "ET"],
                                "resourceTypes": ["Earth"],
                            }
                        }
                    },
                },
                "N": {
                    "entityTypes": {
                        "Moon": {
                            "annotations": {
                                "ae1": "🌕",
                                "ae2": "moon",
                            }
                        }
                    },
                    "actions": {},
                    "annotations": {
                        "a1": "",
                        "a2": "",
                        "a3": "foo",
                    }
                }
            }),
        );

        // attribute annotations
        test_translation(
            r#"
            type Stars = {
                @a1
                "🌕": Long,
                @a2
                "🌎": Long,
                @a3
                "🛰️": {
                  @a4("Rocket")
                  "🚀": Long,
                  "🌌": Long,
                }
            };
            "#,
            &serde_json::json!({
                "": {
                    "entityTypes": {},
                    "actions": {},
                    "commonTypes": {
                        "Stars": {
                            "type": "Record",
                            "attributes": {
                                "🌕": {
                                    "type": "EntityOrCommon",
                                    "name": "Long",
                                    "annotations": {
                                        "a1": "",
                                    }
                                },
                                "🌎": {
                                    "type": "EntityOrCommon",
                                    "name": "Long",
                                    "annotations": {
                                        "a2": "",
                                    }
                                },
                                "🛰️": {
                                    "type": "Record",
                                    "annotations": {
                                        "a3": "",
                                    },
                                    "attributes": {
                                        "🚀": {
                                            "type": "EntityOrCommon",
                                            "name": "Long",
                                            "annotations": {
                                                "a4": "Rocket",
                                            }
                                        },
                                        "🌌": {
                                            "type": "EntityOrCommon",
                                            "name": "Long",
                                        }
                                    }
                                },
                            },
                       },
                    }
                }
            }),
        );
    }

    #[test]
    fn enumerated_entity_types() {
        let src = r#"
        entity Fruits enum ["🍍", "🥭", "🥝"];
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"Fruits".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Enum { choices }, ..} => {
            assert_eq!(Vec::from(choices.clone()), ["🍍", "🥭", "🥝"]);
        });

        let src = r#"
        entity enum enum ["enum"];
        "#;

        let (schema, _) =
            json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        assert_matches!(ns.entity_types.get(&"enum".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Enum { choices }, ..} => {
            assert_eq!(Vec::from(choices.clone()), ["enum"]);
        });
    }
}

mod common_type_references {
    use cool_asserts::assert_matches;

    use crate::extensions::Extensions;
    use crate::validator::{
        json_schema,
        types::{AttributeType, EntityRecordKind, Type},
        SchemaError, ValidatorSchema,
    };

    #[test]
    fn basic() {
        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"
        type a = b;
        type b = Long;
        entity foo {
            a: a,
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_eq!(
            validator_schema
                .get_entity_type(&"foo".parse().unwrap())
                .unwrap()
                .attr("a")
                .unwrap(),
            &AttributeType::new(Type::primitive_long(), true)
        );

        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"
        type a = b;
        type b = c;
        type c = Long;
        entity foo {
            a: a,
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_eq!(
            validator_schema
                .get_entity_type(&"foo".parse().unwrap())
                .unwrap()
                .attr("a")
                .unwrap(),
            &AttributeType::new(Type::primitive_long(), true)
        );

        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace A {
            type a = b;
            type b = c;
            type c = B::a;
            entity foo {
                a: a,
            };
        }
        namespace B {
            type a = Long;
        }
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_eq!(
            validator_schema
                .get_entity_type(&"A::foo".parse().unwrap())
                .unwrap()
                .attr("a")
                .unwrap(),
            &AttributeType::new(Type::primitive_long(), true)
        );
    }

    #[test]
    fn set() {
        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"
        type a = Set<b>;
        type b = Long;
        entity foo {
            a: a,
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_eq!(
            validator_schema
                .get_entity_type(&"foo".parse().unwrap())
                .unwrap()
                .attr("a")
                .unwrap(),
            &AttributeType::new(Type::set(Type::primitive_long()), true)
        );
        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"
        type a = Set<b>;
        type b = c;
        type c = Long;
        entity foo {
            a: a,
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_eq!(
            validator_schema
                .get_entity_type(&"foo".parse().unwrap())
                .unwrap()
                .attr("a")
                .unwrap(),
            &AttributeType::new(Type::set(Type::primitive_long()), true)
        );

        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace A {
            type a = Set<b>;
            type b = c;
            type c = B::a;
            entity foo {
                a: a,
            };
        }
        namespace B {
            type a = Set<Long>;
        }
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_eq!(
            validator_schema
                .get_entity_type(&"A::foo".parse().unwrap())
                .unwrap()
                .attr("a")
                .unwrap(),
            &AttributeType::new(Type::set(Type::set(Type::primitive_long())), true)
        );
    }

    #[test]
    fn record() {
        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"
        type a = {a: b};
        type b = Long;
        entity foo {
            a: a,
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_matches!(
            validator_schema
                .get_entity_type(&"foo".parse().unwrap())
                .unwrap()
                .attr("a")
                .unwrap(),
            AttributeType {
                attr_type: Type::EntityOrRecord(EntityRecordKind::Record { attrs, open_attributes: _ }),
                is_required: true,
                ..
            } => {
                assert_eq!(attrs.get_attr("a").unwrap().attr_type, Type::primitive_long());
            }
        );

        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"
        type a = {a: b};
        type b = c;
        type c = Long;
        entity foo {
            a: a,
        };
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_matches!(
            validator_schema
                .get_entity_type(&"foo".parse().unwrap())
                .unwrap()
                .attr("a")
                .unwrap(),
            AttributeType {
                attr_type: Type::EntityOrRecord(EntityRecordKind::Record { attrs, open_attributes: _ }),
                is_required: true,
                ..
            } => {
                assert_eq!(attrs.get_attr("a").unwrap().attr_type, Type::primitive_long());
            }
        );

        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace A {
            type a = {a: b};
            type b = c;
            type c = B::a;
            entity foo {
                a: a,
            };
        }
        namespace B {
            type a = Set<Long>;
        }
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();
        assert_matches!(
            validator_schema
                .get_entity_type(&"A::foo".parse().unwrap())
                .unwrap()
                .attr("a")
                .unwrap(),
            AttributeType {
                attr_type: Type::EntityOrRecord(EntityRecordKind::Record { attrs, open_attributes: _ }),
                is_required: true,
                ..
            } => {
                assert_eq!(attrs.get_attr("a").unwrap().attr_type, Type::set(Type::primitive_long()));
            }
        );
    }

    #[test]
    fn cycles() {
        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace A {
            type a = {a: b};
            type b = c;
            type c = B::a;
            entity foo {
                a: a,
            };
        }
        namespace B {
            type a = A::b;
        }
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: Result<ValidatorSchema, _> = schema.try_into();
        assert_matches!(
            validator_schema,
            Err(SchemaError::CycleInCommonTypeReferences(_))
        );

        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace A {
            type a = {a: b};
            type b = c;
            type c = B::a;
            entity foo {
                a: a,
            };
        }
        namespace B {
            type a = A::a;
        }
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: Result<ValidatorSchema, _> = schema.try_into();
        assert_matches!(
            validator_schema,
            Err(SchemaError::CycleInCommonTypeReferences(_))
        );

        let (schema, _) = json_schema::Fragment::from_cedarschema_str(
            r#"namespace A {
            type a = B::a;
            entity foo {
                a: a,
            };
        }
        namespace B {
            type a = C::a;
        }
        namespace C {
            type a = A::a;
        }
        "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: Result<ValidatorSchema, _> = schema.try_into();
        assert_matches!(
            validator_schema,
            Err(SchemaError::CycleInCommonTypeReferences(_))
        );
    }
}

/// Tests involving entity tags (RFC 82)
mod entity_tags {
    use crate::extensions::Extensions;
    use crate::validator::json_schema::{self, EntityType, EntityTypeKind};
    use crate::validator::schema::test::utils::collect_warnings;
    use cool_asserts::assert_matches;

    #[test]
    fn basic_examples() {
        let src = "entity E;";
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Ok((frag, warnings)) => {
            assert!(warnings.is_empty());
            assert_matches!(frag.0.get(&None).unwrap().entity_types.get(&"E".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(entity_type), ..} => {
            assert_matches!(&entity_type.tags, None);
            });
        });

        let src = "entity E tags String;";
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Ok((frag, warnings)) => {
            assert!(warnings.is_empty());
            assert_matches!(frag.0.get(&None).unwrap().entity_types.get(&"E".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(entity_type), ..} => {
            assert_matches!(&entity_type.tags, Some(json_schema::Type::Type{ty: json_schema::TypeVariant::EntityOrCommon { type_name }, loc: Some(loc)}) => {
                assert_eq!(&format!("{type_name}"), "String");
                assert_matches!(loc.snippet(), Some("String"));
            });
        });});

        let src = "entity E tags Set<String>;";
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Ok((frag, warnings)) => {
            assert!(warnings.is_empty());
            assert_matches!(frag.0.get(&None).unwrap().entity_types.get(&"E".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(entity_type), ..} => {
            assert_matches!(&entity_type.tags, Some(json_schema::Type::Type{ ty: json_schema::TypeVariant::Set { element }, loc: Some(set_loc)}) => {
                assert_matches!(&**element, json_schema::Type::Type{ ty: json_schema::TypeVariant::EntityOrCommon { type_name }, loc: Some(elt_loc)} => {
                    assert_eq!(&format!("{type_name}"), "String");
                    assert_matches!(set_loc.snippet(), Some("Set<String>"));
                    assert_matches!(elt_loc.snippet(), Some("String"));
                });
            });
        });});

        let src = "entity E { foo: String } tags { foo: String };";
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Ok((frag, warnings)) => {
            assert!(warnings.is_empty());
            assert_matches!(frag.0.get(&None).unwrap().entity_types.get(&"E".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(entity_type), ..} => {
            assert_matches!(&entity_type.tags, Some(json_schema::Type::Type{ ty: json_schema::TypeVariant::Record(rty), loc: Some(rec_loc)}) => {
                assert_matches!(rty.attributes.get("foo"), Some(json_schema::TypeOfAttribute { ty, required, .. }) => {
                    assert_matches!(ty, json_schema::Type::Type { ty: json_schema::TypeVariant::EntityOrCommon { type_name }, loc: Some(foo_loc) } => {
                        assert_eq!(&format!("{type_name}"), "String");
                        assert_matches!(rec_loc.snippet(), Some("{ foo: String }"));
                        assert_matches!(foo_loc.snippet(), Some("String"));
                    });
                    assert!(*required);
                });
            });
        });});

        let src = "type T = String; entity E tags T;";
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Ok((frag, warnings)) => {
            assert!(warnings.is_empty());
            assert_matches!(frag.0.get(&None).unwrap().entity_types.get(&"E".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(entity_type), ..} => {
            assert_matches!(&entity_type.tags, Some(json_schema::Type::Type{ ty: json_schema::TypeVariant::EntityOrCommon { type_name }, loc: Some(loc)}) => {
                assert_eq!(&format!("{type_name}"), "T");
                assert_matches!(loc.snippet(), Some("T"));
            });
        });});

        let src = "entity E tags E;";
        assert_matches!(collect_warnings(json_schema::Fragment::from_cedarschema_str(src, Extensions::all_available())), Ok((frag, warnings)) => {
            assert!(warnings.is_empty());
            assert_matches!(frag.0.get(&None).unwrap().entity_types.get(&"E".parse().unwrap()).unwrap(), EntityType { kind: EntityTypeKind::Standard(entity_type), ..} => {
            assert_matches!(&entity_type.tags, Some(json_schema::Type::Type{ ty: json_schema::TypeVariant::EntityOrCommon { type_name }, loc: Some(loc)}) => {
                assert_eq!(&format!("{type_name}"), "E");
                assert_matches!(loc.snippet(), Some("E"));
            });
        });});
    }
}

pub(crate) const SPECIAL_IDS: [&str; 18] = [
    "principal",
    "action",
    "resource",
    "context",
    "true",
    "false",
    "permit",
    "forbid",
    "when",
    "unless",
    "in",
    "has",
    "like",
    "is",
    "if",
    "then",
    "else",
    "__cedar",
];

// RFC 48 test cases
mod annotations {
    use cool_asserts::assert_matches;

    use crate::validator::cedar_schema::parser::parse_schema;

    use super::SPECIAL_IDS;

    // test if annotation keys can be any id
    #[test]
    fn any_id() {
        for id in SPECIAL_IDS {
            let schema_str = format!("@{id} entity User {{}};");
            assert_matches!(parse_schema(&schema_str), Ok(_));
        }
    }

    #[test]
    fn no_keys() {
        assert_matches!(
            parse_schema(
                r#"
        @doc("This entity defines our central user type")
entity User {
    @manager
    manager : User,
    @team
    team : String
};
        "#
            ),
            Ok(_)
        );
    }

    #[test]
    fn duplicate_keys() {
        assert_matches!(
            parse_schema(
                r#"
        @doc("This entity defines our central user type")
        @doc
entity User {
    @manager
    manager : User,
    @team
    team : String
};
        "#
            ),
            Err(errs) => {
                assert_eq!(errs.0.as_ref().first().to_string(), "duplicate annotations: `doc`");
            }
        );
    }

    #[test]
    fn rfc_examples() {
        // basic
        assert_matches!(
            parse_schema(
                r#"
        @doc("This entity defines our central user type")
entity User {
    manager : User,
    team : String
};
        "#
            ),
            Ok(_)
        );
        // basic + namespace
        assert_matches!(
            parse_schema(
                r#"
        @doc("this is namespace foo")
        namespace foo {
@doc("This entity defines our central user type")
entity User {
    manager : User,
    team : String
};
    }
        "#
            ),
            Ok(_)
        );
        // entity attribute annotation
        assert_matches!(
            parse_schema(
                r#"
@doc("This entity defines our central user type")
entity User {
    manager : User,

    @doc("Which team user belongs to")
    @docLink("https://schemaDocs.example.com/User/team")
    team : String
};
"#
            ),
            Ok(_)
        );
        // full example
        assert_matches!(
            parse_schema(
                r#"
        @doc("this is the namespace")
namespace TinyTodo {
    @doc("a common type representing a task")
    type Task = {
        "id": Long,
        "name": String,
        "state": String,
    };
    @doc("a common type representing a set of tasks")
    type Tasks = Set<Task>;

    @doc1("an entity type representing a list")
    @doc2("any entity type is a child of type `Application`")
    entity List in [Application] = {
        @doc("editors of a list")
        "editors": Team,
        "name": String,
        "owner": User,
        @doc("readers of a list")
        "readers": Team,
        "tasks": Tasks,
    };

    @doc("actions that a user can operate on a list")
    action DeleteList, GetList, UpdateList appliesTo {
        principal: [User],
        resource: [List]
    };
}"#
            ),
            Ok(_)
        );
    }
}
