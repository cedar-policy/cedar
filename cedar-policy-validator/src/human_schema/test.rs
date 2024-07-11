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

// PANIC SAFETY: unit tests
#[allow(clippy::panic)]
#[cfg(test)]
mod demo_tests {

    use std::{
        collections::HashMap,
        iter::{empty, once},
    };

    use cedar_policy_core::extensions::Extensions;
    use cedar_policy_core::test_utils::{expect_err, ExpectedErrorMessageBuilder};
    use cool_asserts::assert_matches;
    use smol_str::ToSmolStr;

    use crate::{
        human_schema::{self, ast::PR, err::ToJsonSchemaError},
        ActionType, ApplySpec, AttributesOrContext, EntityType, HumanSchemaError,
        NamespaceDefinition, RawName, SchemaFragment, SchemaTypeVariant, TypeOfAttribute,
    };

    use itertools::Itertools;
    use miette::Diagnostic;

    #[test]
    fn no_applies_to() {
        let src = r#"
            action "Foo";
        "#;
        let (schema, _) = SchemaFragment::from_str_natural(src, Extensions::none()).unwrap();
        let foo = schema.0.get(&None).unwrap().actions.get("Foo").unwrap();
        assert_matches!(foo,
            ActionType {
                applies_to : Some(ApplySpec {
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
        match SchemaFragment::from_str_natural(src, Extensions::none()) {
            Ok(_) => panic!("Should have failed to parse!"),
            Err(e) => expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `resource` declaration for `Foo`. Actions must define both a `principals` and `resources` field")
                    .exactly_one_underline("\"Foo\"")
                    .build(),
            ),
        }
    }

    #[test]
    fn just_principal() {
        let src = r#"
        entity a;
        action "Foo" appliesTo { principal: a, context: {}  };
        "#;

        match SchemaFragment::from_str_natural(src, Extensions::none()) {
            Ok(_) => panic!("Should have failed to parse!"),
            Err(e) => expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `resource` declaration for `Foo`. Actions must define both a `principals` and `resources` field")
                    .exactly_one_underline("\"Foo\"")
                    .build(),
            )
        }
    }

    #[test]
    fn just_resource() {
        let src = r#"
        entity a;
        action "Foo" appliesTo { resource: a, context: {}  };
        "#;
        match SchemaFragment::from_str_natural(src, Extensions::none()) {
            Ok(_) => panic!("Should have failed to parse!"),
            Err(e) => expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `principal` declaration for `Foo`. Actions must define both a `principals` and `resources` field")
                    .exactly_one_underline("\"Foo\"")
                    .build(),
            )
        }
    }

    #[test]
    fn resource_only() {
        let src = r#"
            entity a;
            action "Foo" appliesTo {
                resource : [a]
            };
        "#;
        match SchemaFragment::from_str_natural(src, Extensions::all_available()) {
            Ok(_) => panic!("Should have failed to parse!"),
            Err(e) => expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `principal` declaration for `Foo`. Actions must define both a `principals` and `resources` field")
                    .exactly_one_underline("\"Foo\"")
                    .build(),
            )
        }
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
        match SchemaFragment::from_str_natural(src, Extensions::all_available()) {
            Ok(_) => panic!("Should have failed to parse!"),
            Err(e) => expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `principal` declaration for `Foo`. Actions must define both a `principals` and `resources` field")
                    .exactly_one_underline("\"Foo\"")
                    .build(),
            )
        }
    }

    #[test]
    fn principal_only() {
        let src = r#"
            entity a;
            action "Foo" appliesTo {
                principal: [a]
            };
        "#;
        match SchemaFragment::from_str_natural(src, Extensions::all_available()) {
            Ok(_) => panic!("Should have failed to parse!"),
            Err(e) => expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `resource` declaration for `Foo`. Actions must define both a `principals` and `resources` field")
                    .exactly_one_underline("\"Foo\"")
                    .build(),
            )
        }
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
        match SchemaFragment::from_str_natural(src, Extensions::all_available()) {
            Ok(_) => panic!("Should have failed to parse!"),
            Err(e) => expect_err(
                src,
                &miette::Report::new(e),
                &ExpectedErrorMessageBuilder::error("error parsing schema: missing `resource` declaration for `Foo`. Actions must define both a `principals` and `resources` field")
                    .exactly_one_underline("\"Foo\"")
                    .build(),
            )
        }
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
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let unqual = schema.0.get(&None).unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(foo,
                ActionType {
                    applies_to : Some(ApplySpec {
                        resource_types,
                        principal_types,
                        ..
                    }),
                    ..
                } =>
                {
                    assert_matches!(principal_types.as_slice(), [a,b] => {
                        assert_eq!(a, &"a".parse().unwrap());
                        assert_eq!(b, &"b".parse().unwrap());
                });
                assert_matches!(resource_types.as_slice(), [c,d] =>  {
                        assert_eq!(c, &"c".parse().unwrap());
                        assert_eq!(d, &"d".parse().unwrap());

                })
            }
            ,
        );
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
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let unqual = schema.0.get(&None).unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(foo,
                ActionType {
                    applies_to : Some(ApplySpec {
                        resource_types,
                        principal_types,
                        ..
                    }),
                    ..
                } =>
                {
                    assert_matches!(principal_types.as_slice(), [a,b] => {
                        assert_eq!(a, &"a".parse().unwrap());
                        assert_eq!(b, &"b".parse().unwrap());
                });
                assert_matches!(resource_types.as_slice(), [c,d] =>  {
                        assert_eq!(c, &"c".parse().unwrap());
                        assert_eq!(d, &"d".parse().unwrap());

                })
            }
            ,
        );
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
        // Can't unwrap here as impl iter doesn't implement debug
        let err = match SchemaFragment::from_str_natural(src, Extensions::all_available()) {
            Err(e) => e,
            _ => panic!("Should have failed to parse"),
        };
        assert_matches!(err, crate::HumanSchemaError::Parsing(err) => {
            assert_matches!(err.inner(), human_schema::parser::HumanSyntaxParseErrors::JsonError(json_errs) => {
                assert!(json_errs
                    .iter()
                    .any(|err| {
                        matches!(
                            err,
                            ToJsonSchemaError::DuplicatePrincipalOrResource {
                                kind: PR::Principal,
                                ..
                            }
                        )
                    })
                );
            });
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
        // Can't unwrap here as impl iter doesn't implement debug
        let err = match SchemaFragment::from_str_natural(src, Extensions::all_available()) {
            Err(e) => e,
            _ => panic!("Should have failed to parse"),
        };
        assert_matches!(err,
        crate::HumanSchemaError::Parsing(err) => assert_matches!(err.inner(),
            human_schema::parser::HumanSyntaxParseErrors::JsonError(json_errs) => {
                assert!(json_errs
                    .iter()
                    .any(|err| {
                        matches!(
                            err,
                            ToJsonSchemaError::DuplicatePrincipalOrResource {
                                kind: PR::Resource,
                                ..
                            }
                        )
                    }));
            }));
    }

    #[test]
    fn empty_appliesto() {
        let action = ActionType::<RawName> {
            attributes: None,
            applies_to: None,
            member_of: None,
        };
        let namespace = NamespaceDefinition::new(empty(), once(("foo".to_smolstr(), action)));
        let fragment = SchemaFragment(HashMap::from([(Some("bar".parse().unwrap()), namespace)]));
        let as_src = fragment.as_natural_schema().unwrap();
        let expected = r#"action "foo";"#;
        assert!(as_src.contains(expected), "src was:\n`{as_src}`");
    }

    #[test]
    fn context_is_common_type() {
        assert!(SchemaFragment::from_str_natural(
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
        )
        .is_ok());
        assert!(SchemaFragment::from_str_natural(
            r#"
    type flag = { value: __cedar::Bool };
    action "Foo" appliesTo {
        context: flag,
        principal: [E],
        resource: [E]
    };
"#,
            Extensions::all_available(),
        )
        .is_ok());
        assert!(SchemaFragment::from_str_natural(
            r#"
namespace Bar { type empty = {}; }
action "Foo" appliesTo {
    context: Bar::empty,
    principal: [E],
    resource: [E]
};
"#,
            Extensions::all_available(),
        )
        .is_ok());
        assert!(SchemaFragment::from_str_natural(
            r#"
namespace Bar { type flag = { value: Bool }; }
namespace Baz {action "Foo" appliesTo {
    context: Bar::flag,
    principal: [E],
    resource: [E]
};}
"#,
            Extensions::all_available(),
        )
        .is_ok());
        assert!(SchemaFragment::from_str_natural(
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
        )
        .is_ok());
    }

    #[test]
    fn print_actions() {
        let namespace = NamespaceDefinition {
            common_types: HashMap::new(),
            entity_types: HashMap::from([(
                "a".parse().unwrap(),
                EntityType::<RawName> {
                    member_of_types: vec![],
                    shape: AttributesOrContext::<RawName>::default(),
                },
            )]),
            actions: HashMap::from([(
                "j".to_smolstr(),
                ActionType::<RawName> {
                    attributes: None,
                    applies_to: Some(ApplySpec::<RawName> {
                        resource_types: vec![],
                        principal_types: vec!["a".parse().unwrap()],
                        context: AttributesOrContext::<RawName>::default(),
                    }),
                    member_of: None,
                },
            )]),
        };
        let fragment = SchemaFragment(HashMap::from([(None, namespace)]));
        let src = fragment.as_natural_schema().unwrap();
        assert!(src.contains(r#"action "j";"#), "schema was: `{src}`")
    }

    #[test]
    fn fully_qualified_actions() {
        let (_, _) = SchemaFragment::from_str_natural(
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
        match SchemaFragment::from_str_natural(
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
        ) {
            Ok(_) => panic!("this is not a valid schema"),
            Err(err) => {
                assert_matches!(err, HumanSchemaError::Parsing(err) => {
                    assert_matches!(err.inner(), human_schema::parser::HumanSyntaxParseErrors::NaturalSyntaxError(errs) => {
                        assert!(errs.to_smolstr().contains("Invalid escape codes"));
                    });
                });
            }
        }
    }

    #[test]
    fn test_github() {
        let (fragment, warnings) = SchemaFragment::from_str_natural(
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
        assert!(warnings.collect::<Vec<_>>().is_empty());
        let github = fragment
            .0
            .get(&Some("GitHub".parse().unwrap()))
            .expect("`Github` name space did not exist");
        // User
        let user = github
            .entity_types
            .get(&"User".parse().unwrap())
            .expect("No `User`");
        assert_empty_records(user);
        assert_eq!(
            &user.member_of_types,
            &vec!["UserGroup".parse().unwrap(), "Team".parse().unwrap()]
        );
        // UserGroup
        let usergroup = github
            .entity_types
            .get(&"UserGroup".parse().unwrap())
            .expect("No `UserGroup`");
        assert_empty_records(usergroup);
        assert_eq!(
            &usergroup.member_of_types,
            &vec!["UserGroup".parse().unwrap()]
        );
        // Repository
        let repo = github
            .entity_types
            .get(&"Repository".parse().unwrap())
            .expect("No `Repository`");
        assert!(repo.member_of_types.is_empty());
        let groups = ["readers", "writers", "triagers", "admins", "maintainers"];
        for group in groups {
            match &repo.shape.0 {
                crate::SchemaType::Type(SchemaTypeVariant::Record {
                    attributes,
                    additional_attributes: false,
                }) => {
                    let expected = SchemaTypeVariant::Entity {
                        name: "UserGroup".parse().unwrap(),
                    };
                    let attribute = attributes.get(group).expect("No attribute `{group}`");
                    assert_has_type(attribute, expected);
                }
                _ => panic!("Shape was not a record"),
            }
        }
        let issue = github
            .entity_types
            .get(&"Issue".parse().unwrap())
            .expect("No `Issue`");
        assert!(issue.member_of_types.is_empty());
        match &issue.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes: false,
            }) => {
                let attribute = attributes.get("repo").expect("No `repo`");
                assert_has_type(
                    attribute,
                    SchemaTypeVariant::Entity {
                        name: "Repository".parse().unwrap(),
                    },
                );
                let attribute = attributes.get("reporter").expect("No `repo`");
                assert_has_type(
                    attribute,
                    SchemaTypeVariant::Entity {
                        name: "User".parse().unwrap(),
                    },
                );
            }
            _ => panic!("bad type on `Issue`"),
        }
        let org = github
            .entity_types
            .get(&"Org".parse().unwrap())
            .expect("No `Org`");
        assert!(org.member_of_types.is_empty());
        let groups = ["members", "owners", "memberOfTypes"];
        for group in groups {
            match &org.shape.0 {
                crate::SchemaType::Type(SchemaTypeVariant::Record {
                    attributes,
                    additional_attributes: false,
                }) => {
                    let expected = SchemaTypeVariant::Entity {
                        name: "UserGroup".parse().unwrap(),
                    };
                    let attribute = attributes.get(group).expect("No attribute `{group}`");
                    assert_has_type(attribute, expected);
                }
                _ => panic!("Shape was not a record"),
            }
        }
    }

    fn assert_has_type<N: std::fmt::Debug + PartialEq>(
        e: &TypeOfAttribute<N>,
        expected: SchemaTypeVariant<N>,
    ) {
        assert!(e.required, "Attribute was not required");
        assert_matches!(&e.ty, crate::SchemaType::Type(t) => assert_eq!(t, &expected));
    }

    fn assert_empty_records<N: std::fmt::Debug>(etyp: &EntityType<N>) {
        assert_matches!(&etyp.shape.0,
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes: false,
            }) => assert!(attributes.is_empty(), "Record should be empty")
        );
    }

    #[test]
    fn test_doc_cloud() {
        let (fragment, warnings) = SchemaFragment::from_str_natural(
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
        assert!(warnings.collect::<Vec<_>>().is_empty());
        let doccloud = fragment
            .0
            .get(&Some("DocCloud".parse().unwrap()))
            .expect("No `DocCloud` namespace");
        let user = doccloud
            .entity_types
            .get(&"User".parse().unwrap())
            .expect("No `User`");
        assert_eq!(&user.member_of_types, &vec!["Group".parse().unwrap()]);
        match &user.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes: false,
            }) => {
                assert_has_type(
                    attributes.get("personalGroup").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "Group".parse().unwrap(),
                    },
                );
                assert_has_type(
                    attributes.get("blocked").unwrap(),
                    SchemaTypeVariant::Set {
                        element: Box::new(crate::SchemaType::Type(SchemaTypeVariant::Entity {
                            name: "User".parse().unwrap(),
                        })),
                    },
                );
            }
            _ => panic!("Wrong type"),
        }
        let group = doccloud
            .entity_types
            .get(&"Group".parse().unwrap())
            .expect("No `Group`");
        assert_eq!(
            &group.member_of_types,
            &vec!["DocumentShare".parse().unwrap()]
        );
        match &group.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes: false,
            }) => {
                assert_has_type(
                    attributes.get("owner").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "User".parse().unwrap(),
                    },
                );
            }
            _ => panic!("Wrong type"),
        }
        let document = doccloud
            .entity_types
            .get(&"Document".parse().unwrap())
            .expect("No `Group`");
        assert!(document.member_of_types.is_empty());
        match &document.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes: false,
            }) => {
                assert_has_type(
                    attributes.get("owner").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "User".parse().unwrap(),
                    },
                );
                assert_has_type(
                    attributes.get("isPrivate").unwrap(),
                    SchemaTypeVariant::Boolean,
                );
                assert_has_type(
                    attributes.get("publicAccess").unwrap(),
                    SchemaTypeVariant::String,
                );
                assert_has_type(
                    attributes.get("viewACL").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "DocumentShare".parse().unwrap(),
                    },
                );
                assert_has_type(
                    attributes.get("modifyACL").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "DocumentShare".parse().unwrap(),
                    },
                );
                assert_has_type(
                    attributes.get("manageACL").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "DocumentShare".parse().unwrap(),
                    },
                );
            }
            _ => panic!("Wrong type"),
        }
        let document_share = doccloud
            .entity_types
            .get(&"DocumentShare".parse().unwrap())
            .expect("No `DocumentShare`");
        assert!(document_share.member_of_types.is_empty());
        assert_empty_records(document_share);

        let public = doccloud
            .entity_types
            .get(&"Public".parse().unwrap())
            .expect("No `Public`");
        assert_eq!(
            &public.member_of_types,
            &vec!["DocumentShare".parse().unwrap()]
        );
        assert_empty_records(public);

        let drive = doccloud
            .entity_types
            .get(&"Drive".parse().unwrap())
            .expect("No `Drive`");
        assert!(drive.member_of_types.is_empty());
        assert_empty_records(drive);
    }

    #[test]
    fn simple_action() {
        let src = r#"
        entity A;
        entity B;
        action Foo appliesTo { principal : A, resource : B  };
        "#;
        let (_, warnings) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        assert!(warnings.collect::<Vec<_>>().is_empty());
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
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        assert!(warnings.collect::<Vec<_>>().is_empty());
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
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        assert!(warnings.collect::<Vec<_>>().is_empty());
        let service = fragment.0.get(&Some("Service".parse().unwrap())).unwrap();
        let resource = service
            .entity_types
            .get(&"Resource".parse().unwrap())
            .unwrap();
        match &resource.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes,
            }) => {
                assert!(!additional_attributes);
                let TypeOfAttribute { ty, required } = attributes.get("tag").unwrap();
                assert!(required);
                match ty {
                    crate::SchemaType::CommonTypeRef { type_name } => {
                        assert_eq!(type_name, &"AWS::Tag".parse().unwrap())
                    }
                    _ => panic!("Wrong type for attribute"),
                }
            }
            _ => panic!("Wrong type for shape"),
        }
    }

    #[test]
    fn expected_tokens() {
        #[track_caller]
        fn assert_labeled_span(src: &str, label: impl Into<String>) {
            assert_matches!(SchemaFragment::from_str_natural(src, Extensions::all_available()).map(|(s, _)| s), Err(e) => {
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
            "expected `}`, identifier, or string literal",
        );
        assert_labeled_span("entity User { name:", "expected `{`, identifier, or `Set`");
    }
}

#[cfg(test)]
mod parser_tests {
    use crate::human_schema::parser::parse_schema;

    #[test]
    fn mixed_decls() {
        let res = parse_schema(
            r#"
        entity A;
        namespace Foo {}
        type B = A;
        "#,
        );
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn entity_decl_basic() {
        let res = parse_schema(
            r#"
    entity A;
        "#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    entity "A";
    "#,
        );
        assert!(res.is_err(), "{res:?}");
        let res = parse_schema(
            r#"
    entity A in B;
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    entity A in [B];
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    entity A in [B, C];
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    entity A in [B, C];
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    entity A in [B, C] {};
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    entity A in [B, C] = {};
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    entity A in [B, C] = {foo: String};
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    entity A in [B, C] = {foo: String,};
"#,
        );
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn action_decl_basic() {
        let res = parse_schema(
            r#"
    action A;
        "#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    action "A";
    "#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in B;
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B];
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B, C];
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B, C];
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo {};
"#,
        );
        assert!(res.is_err(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { context: {}};
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: []};
"#,
        );
        assert!(res.is_err(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: X, resource: [Y]};
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: X, resource: [Y,]};
"#,
        );
        assert!(res.is_err(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: X, resource: [Y,Z]} attributes {};
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    action A in [B, C] appliesTo { principal: X, resource: [Y,Z]} = attributes {};
"#,
        );
        assert!(res.is_err(), "{res:?}");
    }

    #[test]
    fn common_type_decl_basic() {
        let res = parse_schema(
            r#"
    type A = B;
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    type "A" = B;
"#,
        );
        assert!(res.is_err(), "{res:?}");
        let res = parse_schema(
            r#"
    type A = "B";
"#,
        );
        assert!(res.is_err(), "{res:?}");
        let res = parse_schema(
            r#"
    type A = B::C;
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    type A = Bool;
    type B = __cedar::Bool;
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    type A = Long;
    type B = __cedar::Long;
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    type A = String;
    type B = __cedar::String;
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    type A = ipaddr;
    type B = __cedar::ipaddr;
"#,
        );
        assert!(res.is_ok(), "{res:?}");
        let res = parse_schema(
            r#"
    type A = decimal;
    type B = __cedar::decimal;
"#,
        );
        assert!(res.is_ok(), "{res:?}");
    }
}

// PANIC SAFETY: tests
#[allow(clippy::unreachable)]
// PANIC SAFETY: tests
#[allow(clippy::panic)]
#[cfg(test)]
mod translator_tests {
    use cedar_policy_core::ast as cedar_ast;
    use cedar_policy_core::extensions::Extensions;
    use cedar_policy_core::FromNormalizedStr;

    use crate::{
        types::{EntityLUB, Type},
        SchemaFragment, SchemaTypeVariant, TypeOfAttribute, ValidatorSchema,
    };

    #[test]
    fn use_reserved_namespace() {
        let schema = SchemaFragment::from_str_natural(
            r#"
          namespace __cedar {}
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_err(), "__cedar namespace shouldn't be allowed");

        let schema = SchemaFragment::from_str_natural(
            r#"
          namespace __cedar::Foo {}
        "#,
            Extensions::all_available(),
        );
        assert!(
            schema.is_err(),
            "__cedar::Foo namespace shouldn't be allowed"
        );
    }

    #[test]
    fn duplicate_namespace() {
        let schema = SchemaFragment::from_str_natural(
            r#"
          namespace A {}
          namespace A {}
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_err(), "duplicate namespaces shouldn't be allowed");
    }

    #[test]
    fn duplicate_action_types() {
        let schema = SchemaFragment::from_str_natural(
            r#"
          action A;
          action A appliesTo { context: {}};
        "#,
            Extensions::all_available(),
        );
        assert!(
            schema.is_err(),
            "duplicate action type names shouldn't be allowed: "
        );
        let schema = SchemaFragment::from_str_natural(
            r#"
          action A;
          action "A";
        "#,
            Extensions::all_available(),
        );
        assert!(
            schema.is_err(),
            "duplicate action type names shouldn't be allowed"
        );

        let schema = SchemaFragment::from_str_natural(
            r#"
            namespace Foo {
          action A;
          action "A";
            };
        "#,
            Extensions::all_available(),
        );
        assert!(
            schema.is_err(),
            "duplicate action type names shouldn't be allowed"
        );

        let schema = SchemaFragment::from_str_natural(
            r#"
          namespace X { action A; }
          action A;
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_ok());
    }

    #[test]
    fn duplicate_entity_types() {
        let schema = SchemaFragment::from_str_natural(
            r#"
          entity A;
          entity A {};
        "#,
            Extensions::all_available(),
        );
        assert!(
            schema.is_err(),
            "duplicate entity type names shouldn't be allowed"
        );
        assert!(SchemaFragment::from_str_natural(
            r#"
          entity A,A {};
        "#,
            Extensions::all_available(),
        )
        .is_err());
        assert!(SchemaFragment::from_str_natural(
            r#"
          namespace X { entity A; }
          entity A {};
        "#,
            Extensions::all_available(),
        )
        .is_ok());
    }

    #[test]
    fn duplicate_common_types() {
        let schema = SchemaFragment::from_str_natural(
            r#"
          type A = Bool;
          type A = Long;
        "#,
            Extensions::all_available(),
        );
        assert!(
            schema.is_err(),
            "duplicate common type names shouldn't be allowed"
        );
        assert!(SchemaFragment::from_str_natural(
            r#"
          namespace X { type A = Bool; }
          type A = Long;
        "#,
            Extensions::all_available(),
        )
        .is_ok());
    }

    #[test]
    fn type_name_resolution_basic() {
        let (schema, _) = SchemaFragment::from_str_natural(
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
        )
        .expect("should be a valid natural schema");
        let validator_schema: ValidatorSchema =
            schema.try_into().expect("should be a valid schema");
        for (name, ety) in validator_schema.entity_types() {
            match name.to_string().as_ref() {
                "Demo::Host" => {
                    for (attr_name, attr) in ety.attributes() {
                        match attr_name.as_ref() {
                            "ip" => assert!(
                                matches!(
                                    &attr.attr_type,
                                    crate::types::Type::EntityOrRecord(
                                        crate::types::EntityRecordKind::Record {
                                            attrs: _,
                                            open_attributes: _
                                        }
                                    )
                                ),
                                "wrong type for attr `ip`"
                            ),
                            "bandwidth" => assert!(
                                matches!(&attr.attr_type, crate::types::Type::ExtensionType { name } if name.clone() == cedar_policy_core::ast::Name::from_normalized_str("decimal").unwrap()),
                                "wrong type for attr `bandwidth`"
                            ),
                            _ => unreachable!("unexpected attr: {attr_name}"),
                        }
                    }
                }
                "Demo::String" => {
                    for (attr_name, attr) in ety.attributes() {
                        match attr_name.as_ref() {
                            "groups" => assert!(
                                matches!(&attr.attr_type, crate::types::Type::Set { element_type: Some(t)} if **t == crate::types::Type::Primitive { primitive_type: crate::types::Primitive::String }),
                                "wrong type for attr `groups`"
                            ),
                            _ => unreachable!("unexpected attr: {attr_name}"),
                        }
                    }
                }
                _ => unreachable!("unexpected entity type: {name}"),
            }
        }
    }

    #[test]
    fn type_name_cross_namespace() {
        let (schema, _) = SchemaFragment::from_str_natural(
            r#"namespace A {
                entity B in [X::Y, A::C];
                entity C;
            }
            namespace X {
                entity Y;
            }
            "#,
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema =
            schema.try_into().expect("should be a valid schema");
        for (name, et) in validator_schema.entity_types() {
            if name.to_string() == "A::C" || name.to_string() == "X::Y" {
                assert!(et.descendants.contains(&cedar_ast::EntityType::from(
                    cedar_policy_core::ast::Name::from_normalized_str("A::B").unwrap()
                )));
            } else {
                assert!(et.descendants.is_empty());
            }
        }
    }

    #[test]
    fn type_name_resolution_empty_namespace() {
        let (schema, _) = SchemaFragment::from_str_natural(
            r#"
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
            type id = String;
          }"#,
            Extensions::all_available(),
        )
        .unwrap();
        let demo = schema.0.get(&Some("Demo".parse().unwrap())).unwrap();
        let user = demo.entity_types.get(&"User".parse().unwrap()).unwrap();
        match &user.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes,
            }) => {
                assert!(!additional_attributes);
                let TypeOfAttribute { ty, required } = attributes.get("name").unwrap();
                {
                    assert!(required);
                    let expected = crate::SchemaType::CommonTypeRef {
                        type_name: "id".parse().unwrap(),
                    };
                    assert_eq!(ty, &expected);
                }
                let TypeOfAttribute { ty, required } = attributes.get("email").unwrap();
                {
                    assert!(required);
                    let expected = crate::SchemaType::Type(SchemaTypeVariant::Entity {
                        name: "email_address".parse().unwrap(),
                    });
                    assert_eq!(ty, &expected);
                }
            }
            _ => panic!("Wrong type"),
        }
        let validator_schema: Result<ValidatorSchema, _> = schema.try_into();
        assert!(validator_schema.is_ok());
    }

    // PANIC SAFETY: testing
    #[allow(clippy::unwrap_used)]
    // PANIC SAFETY: testing
    #[allow(clippy::indexing_slicing)]
    #[test]
    fn type_name_resolution_cross_namespace() {
        let (schema, _) = SchemaFragment::from_str_natural(
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
                cedar_policy_core::ast::Name::from_normalized_str("A::B").unwrap(),
            ))
            .unwrap();
        let attr = et.attr("foo").unwrap();
        assert!(
            matches!(&attr.attr_type, crate::types::Type::Primitive { primitive_type } if matches!(primitive_type, crate::types::Primitive::Bool))
        );

        let (schema, _) = SchemaFragment::from_str_natural(
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
                .attributes
                .attrs["foo"]
                .attr_type,
            Type::EntityOrRecord(crate::types::EntityRecordKind::Entity(
                EntityLUB::single_entity("X::Z".parse().unwrap())
            ))
        );
    }

    #[test]
    fn entity_named_namespace() {
        let src = r#"
        entity namespace = {};
        entity Foo in [namespace] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["namespace".parse().unwrap()]);
    }

    #[test]
    fn entity_named_in() {
        // This fails because `in` is reserved
        let src = r#"
        entity in = {};
        entity Foo in [in] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src, Extensions::all_available()).is_err());
    }

    #[test]
    fn entity_named_set() {
        let src = r#"
        entity Set = {};
        entity Foo in [Set] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["Set".parse().unwrap()]);
    }

    #[test]
    fn entity_named_applies_to() {
        let src = r#"
        entity appliesTo = {};
        entity Foo in [appliesTo] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["appliesTo".parse().unwrap()]);
    }

    #[test]
    fn entity_named_principal() {
        let src = r#"
        entity principal = {};
        entity Foo in [principal ] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["principal".parse().unwrap()]);
    }

    #[test]
    fn entity_named_resource() {
        let src = r#"
        entity resource= {};
        entity Foo in [resource] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["resource".parse().unwrap()]);
    }

    #[test]
    fn entity_named_action() {
        let src = r#"
        entity action= {};
        entity Foo in [action] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["action".parse().unwrap()]);
    }

    #[test]
    fn entity_named_context() {
        let src = r#"
        entity context= {};
        entity Foo in [context] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["context".parse().unwrap()]);
    }

    #[test]
    fn entity_named_attributes() {
        let src = r#"
        entity attributes= {};
        entity Foo in [attributes] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["attributes".parse().unwrap()]);
    }

    #[test]
    fn entity_named_bool() {
        let src = r#"
        entity Bool= {};
        entity Foo in [Bool] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["Bool".parse().unwrap()]);
    }

    #[test]
    fn entity_named_long() {
        let src = r#"
        entity Long= {};
        entity Foo in [Long] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["Long".parse().unwrap()]);
    }

    #[test]
    fn entity_named_string() {
        let src = r#"
        entity String= {};
        entity Foo in [String] = {};
        "#;

        let (schema, _) =
            SchemaFragment::from_str_natural(src, Extensions::all_available()).unwrap();
        let ns = schema.0.get(&None).unwrap();
        let foo = ns.entity_types.get(&"Foo".parse().unwrap()).unwrap();
        assert_eq!(foo.member_of_types, vec!["String".parse().unwrap()]);
    }

    #[test]
    fn entity_named_if() {
        let src = r#"
        entity if = {};
        entity Foo in [if] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src, Extensions::all_available()).is_err());
    }

    #[test]
    fn entity_named_like() {
        let src = r#"
        entity like = {};
        entity Foo in [like] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src, Extensions::all_available()).is_err());
    }

    #[test]
    fn entity_named_true() {
        let src = r#"
        entity true = {};
        entity Foo in [true] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src, Extensions::all_available()).is_err());
    }

    #[test]
    fn entity_named_false() {
        let src = r#"
        entity false = {};
        entity Foo in [false] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src, Extensions::all_available()).is_err());
    }

    #[test]
    fn entity_named_has() {
        let src = r#"
        entity has = {};
        entity Foo in [has] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src, Extensions::all_available()).is_err());
    }

    #[test]
    fn multiple_principal_decls() {
        let schema = SchemaFragment::from_str_natural(
            r#"
        entity foo;
        action a appliesTo { principal: A, principal: A };
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_err());

        let schema = SchemaFragment::from_str_natural(
            r#"
        entity foo;
        action a appliesTo { principal: A, resource: B, principal: A };
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_err());
    }

    #[test]
    fn multiple_resource_decls() {
        let schema = SchemaFragment::from_str_natural(
            r#"
        entity foo;
        action a appliesTo { resource: A, resource: A };
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_err());

        let schema = SchemaFragment::from_str_natural(
            r#"
        entity foo;
        action a appliesTo { resource: A, principal: B, resource: A };
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_err());
    }

    #[test]
    fn multiple_context_decls() {
        let schema = SchemaFragment::from_str_natural(
            r#"
        entity foo;
        action a appliesTo { context: A, context: A };
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_err());

        let schema = SchemaFragment::from_str_natural(
            r#"
        entity foo;
        action a appliesTo { principal: C, context: A, context: A };
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_err());

        let schema = SchemaFragment::from_str_natural(
            r#"
        entity foo;
        action a appliesTo { resource: C, context: A, context: A };
        "#,
            Extensions::all_available(),
        );
        assert!(schema.is_err());
    }
}

#[cfg(test)]
mod common_type_references {
    use cool_asserts::assert_matches;

    use crate::{
        types::{AttributeType, EntityRecordKind, Type},
        SchemaError, SchemaFragment, ValidatorSchema,
    };
    use cedar_policy_core::extensions::Extensions;

    #[test]
    fn basic() {
        let (schema, _) = SchemaFragment::from_str_natural(
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

        let (schema, _) = SchemaFragment::from_str_natural(
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

        let (schema, _) = SchemaFragment::from_str_natural(
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
        let (schema, _) = SchemaFragment::from_str_natural(
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
        let (schema, _) = SchemaFragment::from_str_natural(
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

        let (schema, _) = SchemaFragment::from_str_natural(
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
        let (schema, _) = SchemaFragment::from_str_natural(
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
            AttributeType { attr_type: Type::EntityOrRecord(EntityRecordKind::Record { attrs, open_attributes: _ }), is_required: true } if attrs.attrs.get("a").unwrap().attr_type == Type::primitive_long()
        );

        let (schema, _) = SchemaFragment::from_str_natural(
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
            AttributeType { attr_type: Type::EntityOrRecord(EntityRecordKind::Record { attrs, open_attributes: _ }), is_required: true } if attrs.attrs.get("a").unwrap().attr_type == Type::primitive_long()
        );

        let (schema, _) = SchemaFragment::from_str_natural(
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
            AttributeType { attr_type: Type::EntityOrRecord(EntityRecordKind::Record { attrs, open_attributes: _ }), is_required: true } if attrs.attrs.get("a").unwrap().attr_type == Type::set(Type::primitive_long())
        );
    }

    #[test]
    fn cycles() {
        let (schema, _) = SchemaFragment::from_str_natural(
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

        let (schema, _) = SchemaFragment::from_str_natural(
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

        let (schema, _) = SchemaFragment::from_str_natural(
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
