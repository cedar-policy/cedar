// PANIC SAFETY: unit tests
#[allow(clippy::panic)]
#[cfg(test)]
mod demo_tests {

    use std::{
        collections::HashMap,
        iter::{empty, once},
    };

    use cool_asserts::assert_matches;
    use smol_str::ToSmolStr;

    use crate::{
        human_schema::{self, ast::PR, err::ToJsonSchemaError},
        ActionType, ApplySpec, AttributesOrContext, EntityType, HumanSchemaError,
        NamespaceDefinition, SchemaFragment, SchemaTypeVariant, TypeOfAttribute,
    };

    use itertools::Itertools;
    use miette::Diagnostic;

    #[test]
    fn no_applies_to() {
        let src = r#"
            action "Foo";
        "#;
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let foo = schema.0.get("").unwrap().actions.get("Foo").unwrap();
        assert_matches!(foo,
            ActionType { applies_to : Some(ApplySpec { resource_types : Some(resources), principal_types : Some(principals), ..}), .. } => assert!(resources.is_empty() && principals.is_empty())
        );
    }

    #[test]
    fn just_context() {
        let src = r#"
        action "Foo" appliesTo { context: {} };
        "#;
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let foo = schema.0.get("").unwrap().actions.get("Foo").unwrap();
        assert_matches!(
            foo,
            ActionType {
                applies_to: Some(ApplySpec {
                    resource_types: None,
                    principal_types: None,
                    ..
                }),
                ..
            }
        );
    }

    #[test]
    fn just_principal() {
        let src = r#"
        entity a;
        action "Foo" appliesTo { principal: a, context: {}  };
        "#;
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let foo = schema.0.get("").unwrap().actions.get("Foo").unwrap();
        assert_matches!(foo,
            ActionType { applies_to : Some(ApplySpec { resource_types : None, principal_types : Some(principals), ..}), .. } =>
                {
                    match principals.as_slice() {
                        [a] if a == &"a".to_smolstr() => (),
                        _ => panic!("Bad principals")
                    }
                }
        );
    }

    #[test]
    fn just_resource() {
        let src = r#"
        entity a;
        action "Foo" appliesTo { resource: a, context: {}  };
        "#;
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let foo = schema.0.get("").unwrap().actions.get("Foo").unwrap();
        assert_matches!(foo,
            ActionType { applies_to : Some(ApplySpec { resource_types : Some(resources), principal_types : None, ..}), .. } =>
                {
                    match resources.as_slice() {
                        [a] if a == &"a".to_smolstr() => (),
                        _ => panic!("Bad principals")
                    }
                }
        );
    }

    #[test]
    fn resource_only() {
        let src = r#"
            entity a;
            action "Foo" appliesTo {
                resource : [a]
            };
        "#;
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let unqual = schema.0.get("").unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(foo,
                ActionType { applies_to : Some(ApplySpec { resource_types : Some(resources), principal_types : None, .. }  ), ..} =>
                    assert_matches!(resources.as_slice(), [a] => assert_eq!(a.as_ref(), "a"))
            ,
        );
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
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let unqual = schema.0.get("").unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(foo,
                ActionType { applies_to : Some(ApplySpec { resource_types : Some(resources), principal_types : None, .. }  ), ..} =>
                    assert_matches!(resources.as_slice(), [a, b] => {
                        assert_eq!(a.as_ref(), "a");
                        assert_eq!(b.as_ref(), "b")
                    })
            ,
        );
    }

    #[test]
    fn principal_only() {
        let src = r#"
            entity a;
            action "Foo" appliesTo {
                principal: [a]
            };
        "#;
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let unqual = schema.0.get("").unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(foo,
                ActionType { applies_to : Some(ApplySpec { resource_types : None, principal_types : Some(principals), .. }  ), ..} =>
                    assert_matches!(principals.as_slice(), [a] => assert_eq!(a.as_ref(), "a"))
            ,
        );
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
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let unqual = schema.0.get("").unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(foo,
                ActionType { applies_to : Some(ApplySpec { resource_types : None, principal_types : Some(principals), .. }  ), ..} =>
                    assert_matches!(principals.as_slice(), [a,b] => {
                        assert_eq!(a.as_ref(), "a");
                        assert_eq!(b.as_ref(), "b");
                })
            ,
        );
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
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let unqual = schema.0.get("").unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(foo,
                ActionType { applies_to : Some(ApplySpec { resource_types : Some(resources), principal_types : Some(principals), .. }  ), ..} =>
                {
                    assert_matches!(principals.as_slice(), [a,b] => {
                        assert_eq!(a.as_ref(), "a");
                        assert_eq!(b.as_ref(), "b");
                });
                assert_matches!(resources.as_slice(), [c,d] =>  {
                        assert_eq!(c.as_ref(), "c");
                        assert_eq!(d.as_ref(), "d");

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
        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let unqual = schema.0.get("").unwrap();
        let foo = unqual.actions.get("Foo").unwrap();
        assert_matches!(foo,
                ActionType { applies_to : Some(ApplySpec { resource_types : Some(resources), principal_types : Some(principals), .. }  ), ..} =>
                {
                    assert_matches!(principals.as_slice(), [a,b] => {
                        assert_eq!(a.as_ref(), "a");
                        assert_eq!(b.as_ref(), "b");
                });
                assert_matches!(resources.as_slice(), [c,d] =>  {
                        assert_eq!(c.as_ref(), "c");
                        assert_eq!(d.as_ref(), "d");

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
        let err = match SchemaFragment::from_str_natural(src) {
            Err(e) => e,
            _ => panic!("Should have failed to parse"),
        };
        assert_matches!(err,
        crate::HumanSchemaError::Parsing(err) => assert_matches!(err,
            human_schema::parser::HumanSyntaxParseErrors::JsonError(json_errs) => {
                assert!(json_errs
                    .into_iter()
                    .any(|err| {
                        matches!(
                            err,
                            ToJsonSchemaError::DuplicatePR {
                                kind: PR::Principal,
                                ..
                            }
                        )
                    }));
            }));
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
        let err = match SchemaFragment::from_str_natural(src) {
            Err(e) => e,
            _ => panic!("Should have failed to parse"),
        };
        assert_matches!(err,
        crate::HumanSchemaError::Parsing(err) => assert_matches!(err,
            human_schema::parser::HumanSyntaxParseErrors::JsonError(json_errs) => {
                assert!(json_errs
                    .into_iter()
                    .any(|err| {
                        matches!(
                            err,
                            ToJsonSchemaError::DuplicatePR {
                                kind: PR::Resource,
                                ..
                            }
                        )
                    }));
            }));
    }

    #[test]
    fn empty_appliesto() {
        let action = ActionType {
            attributes: None,
            applies_to: None,
            member_of: None,
        };
        let namespace = NamespaceDefinition::new(empty(), once(("foo".to_smolstr(), action)));
        let fragment = SchemaFragment(HashMap::from([("bar".to_smolstr(), namespace)]));
        let as_src = fragment.as_natural_schema().unwrap();
        let expected = r#"action "foo" appliesTo {  context: {}
};"#;
        assert!(as_src.contains(expected), "src was:\n`{as_src}`");
    }

    #[test]
    fn print_actions() {
        let namespace = NamespaceDefinition {
            common_types: HashMap::new(),
            entity_types: HashMap::from([(
                "a".to_smolstr(),
                EntityType {
                    member_of_types: vec![],
                    shape: AttributesOrContext::default(),
                },
            )]),
            actions: HashMap::from([(
                "j".to_smolstr(),
                ActionType {
                    attributes: None,
                    applies_to: Some(ApplySpec {
                        resource_types: Some(vec![]),
                        principal_types: Some(vec!["a".to_smolstr()]),
                        context: AttributesOrContext::default(),
                    }),
                    member_of: None,
                },
            )]),
        };
        let fragment = SchemaFragment(HashMap::from([("".to_smolstr(), namespace)]));
        let src = fragment.as_natural_schema().unwrap();
        assert!(src.contains(r#"action "j" ;"#), "schema was: `{src}`")
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
        ) {
            Ok(_) => panic!("this is not a valid schema"),
            Err(err) => {
                assert_matches!(err, HumanSchemaError::Parsing(human_schema::parser::HumanSyntaxParseErrors::NaturalSyntaxError(errs)) => assert!(errs.to_smolstr().contains("Invalid escape codes")))
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
        )
        .expect("Schema should parse");
        assert!(warnings.collect::<Vec<_>>().is_empty());
        let github = fragment
            .0
            .get("GitHub")
            .expect("`Github` name space did not exist");
        // User
        let user = github.entity_types.get("User").expect("No `User`");
        assert_empty_records(user);
        assert_eq!(
            &user.member_of_types,
            &vec!["UserGroup".to_smolstr(), "Team".to_smolstr()]
        );
        // UserGroup
        let usergroup = github
            .entity_types
            .get("UserGroup")
            .expect("No `UserGroup`");
        assert_empty_records(usergroup);
        assert_eq!(&usergroup.member_of_types, &vec!["UserGroup".to_smolstr()]);
        // Repository
        let repo = github
            .entity_types
            .get("Repository")
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
                        name: "UserGroup".into(),
                    };
                    let attribute = attributes.get(group).expect("No attribute `{group}`");
                    assert_has_type(attribute, expected);
                }
                _ => panic!("Shape was not a record"),
            }
        }
        let issue = github.entity_types.get("Issue").expect("No `Issue`");
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
                        name: "Repository".into(),
                    },
                );
                let attribute = attributes.get("reporter").expect("No `repo`");
                assert_has_type(
                    attribute,
                    SchemaTypeVariant::Entity {
                        name: "User".into(),
                    },
                );
            }
            _ => panic!("bad type on `Issue`"),
        }
        let org = github.entity_types.get("Org").expect("No `Org`");
        assert!(org.member_of_types.is_empty());
        let groups = ["members", "owners", "memberOfTypes"];
        for group in groups {
            match &org.shape.0 {
                crate::SchemaType::Type(SchemaTypeVariant::Record {
                    attributes,
                    additional_attributes: false,
                }) => {
                    let expected = SchemaTypeVariant::Entity {
                        name: "UserGroup".into(),
                    };
                    let attribute = attributes.get(group).expect("No attribute `{group}`");
                    assert_has_type(attribute, expected);
                }
                _ => panic!("Shape was not a record"),
            }
        }
    }

    fn assert_has_type(e: &TypeOfAttribute, expected: SchemaTypeVariant) {
        assert!(e.required, "Attribute was not required");
        match &e.ty {
            crate::SchemaType::Type(t) => assert_eq!(t, &expected),
            _ => panic!("Wrong type"),
        }
    }

    fn assert_empty_records(etyp: &EntityType) {
        match &etyp.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes: false,
            }) => assert!(attributes.is_empty(), "Record should be empty"),
            _ => panic!("Should have an empty record"),
        }
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
        )
        .expect("failed to parse");
        assert!(warnings.collect::<Vec<_>>().is_empty());
        let doccloud = fragment.0.get("DocCloud").expect("No `DocCloud` namespace");
        let user = doccloud.entity_types.get("User").expect("No `User`");
        assert_eq!(&user.member_of_types, &vec!["Group".to_smolstr()]);
        match &user.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes: false,
            }) => {
                assert_has_type(
                    attributes.get("personalGroup").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "Group".into(),
                    },
                );
                assert_has_type(
                    attributes.get("blocked").unwrap(),
                    SchemaTypeVariant::Set {
                        element: Box::new(crate::SchemaType::Type(SchemaTypeVariant::Entity {
                            name: "User".into(),
                        })),
                    },
                );
            }
            _ => panic!("Wrong type"),
        }
        let group = doccloud.entity_types.get("Group").expect("No `Group`");
        assert_eq!(&group.member_of_types, &vec!["DocumentShare".to_smolstr()]);
        match &group.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes: false,
            }) => {
                assert_has_type(
                    attributes.get("owner").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "User".into(),
                    },
                );
            }
            _ => panic!("Wrong type"),
        }
        let document = doccloud.entity_types.get("Document").expect("No `Group`");
        assert!(document.member_of_types.is_empty());
        match &document.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes: false,
            }) => {
                assert_has_type(
                    attributes.get("owner").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "User".into(),
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
                        name: "DocumentShare".into(),
                    },
                );
                assert_has_type(
                    attributes.get("modifyACL").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "DocumentShare".into(),
                    },
                );
                assert_has_type(
                    attributes.get("manageACL").unwrap(),
                    SchemaTypeVariant::Entity {
                        name: "DocumentShare".into(),
                    },
                );
            }
            _ => panic!("Wrong type"),
        }
        let document_share = doccloud
            .entity_types
            .get("DocumentShare")
            .expect("No `DocumentShare`");
        assert!(document_share.member_of_types.is_empty());
        assert_empty_records(document_share);

        let public = doccloud.entity_types.get("Public").expect("No `Public`");
        assert_eq!(&public.member_of_types, &vec!["DocumentShare".to_smolstr()]);
        assert_empty_records(public);

        let drive = doccloud.entity_types.get("Drive").expect("No `Drive`");
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
        let (_, warnings) = SchemaFragment::from_str_natural(src).unwrap();
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

        let (_, warnings) = SchemaFragment::from_str_natural(src).unwrap();
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
        let (fragment, warnings) = SchemaFragment::from_str_natural(src).unwrap();
        assert!(warnings.collect::<Vec<_>>().is_empty());
        let service = fragment.0.get("Service").unwrap();
        let resource = service.entity_types.get("Resource").unwrap();
        match &resource.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes,
            }) => {
                assert!(!additional_attributes);
                let TypeOfAttribute { ty, required } = attributes.get("tag").unwrap();
                assert!(required);
                match ty {
                    crate::SchemaType::TypeDef { type_name } => {
                        assert_eq!(type_name, &"AWS::Tag".to_smolstr())
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
            assert_matches!(SchemaFragment::from_str_natural(src).map(|(s, _)| s), Err(e) => {
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
    use cedar_policy_core::FromNormalizedStr;
    use smol_str::ToSmolStr;

    use crate::{SchemaError, SchemaFragment, SchemaTypeVariant, TypeOfAttribute, ValidatorSchema};

    #[test]
    fn use_reserved_namespace() {
        let schema = SchemaFragment::from_str_natural(
            r#"
          namespace __cedar {}
        "#,
        );
        assert!(schema.is_err(), "duplicate namespaces shouldn't be allowed");

        let schema = SchemaFragment::from_str_natural(
            r#"
          namespace __cedar::Foo {}
        "#,
        );
        assert!(schema.is_err(), "duplicate namespaces shouldn't be allowed");
    }

    #[test]
    fn duplicate_namespace() {
        let schema = SchemaFragment::from_str_natural(
            r#"
          namespace A {}
          namespace A {}
        "#,
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
        );
        assert!(
            schema.is_err(),
            "duplicate entity type names shouldn't be allowed"
        );
        assert!(SchemaFragment::from_str_natural(
            r#"
          entity A,A {};
        "#,
        )
        .is_err());
        assert!(SchemaFragment::from_str_natural(
            r#"
          namespace X { entity A; }
          entity A {};
        "#,
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
        )
        .unwrap();
        let validator_schema: ValidatorSchema =
            schema.try_into().expect("should be a valid schema");
        for (name, et) in validator_schema.entity_types() {
            if name.to_string() == "A::C" || name.to_string() == "X::Y" {
                assert!(et
                    .descendants
                    .contains(&cedar_policy_core::ast::Name::from_normalized_str("A::B").unwrap()));
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
        )
        .unwrap();
        let demo = schema.0.get("Demo").unwrap();
        let user = demo.entity_types.get("User").unwrap();
        match &user.shape.0 {
            crate::SchemaType::Type(SchemaTypeVariant::Record {
                attributes,
                additional_attributes,
            }) => {
                assert!(!additional_attributes);
                let TypeOfAttribute { ty, required } = attributes.get("name").unwrap();
                {
                    assert!(required);
                    let expected = crate::SchemaType::TypeDef {
                        type_name: "id".into(),
                    };
                    assert_eq!(ty, &expected);
                }
                let TypeOfAttribute { ty, required } = attributes.get("email").unwrap();
                {
                    assert!(required);
                    let expected = crate::SchemaType::Type(SchemaTypeVariant::Entity {
                        name: "email_address".into(),
                    });
                    assert_eq!(ty, &expected);
                }
            }
            _ => panic!("Wrong type"),
        }
        let validator_schema: Result<ValidatorSchema, _> = schema.try_into();
        assert!(validator_schema.is_ok());
    }

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
        )
        .unwrap();
        let validator_schema: ValidatorSchema =
            schema.try_into().expect("should be a valid schema");
        let et = validator_schema
            .get_entity_type(&cedar_policy_core::ast::Name::from_normalized_str("A::B").unwrap())
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
                type Y = X::Y;
                entity Y;
            }
            "#,
        )
        .unwrap();
        let validator_schema: Result<ValidatorSchema, _> = schema.try_into();
        assert!(
            validator_schema.is_err()
                && matches!(
                    validator_schema.unwrap_err(),
                    SchemaError::UndeclaredCommonTypes(_)
                )
        );
    }

    #[test]
    fn entity_named_namespace() {
        let src = r#"
        entity namespace = {};
        entity Foo in [namespace] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["namespace".to_smolstr()]);
    }

    #[test]
    fn entity_named_in() {
        // This fails because `in` is reserved
        let src = r#"
        entity in = {};
        entity Foo in [in] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src).is_err());
    }

    #[test]
    fn entity_named_set() {
        let src = r#"
        entity Set = {};
        entity Foo in [Set] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["Set".to_smolstr()]);
    }

    #[test]
    fn entity_named_applies_to() {
        let src = r#"
        entity appliesTo = {};
        entity Foo in [appliesTo] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["appliesTo".to_smolstr()]);
    }

    #[test]
    fn entity_named_principal() {
        let src = r#"
        entity principal = {};
        entity Foo in [principal ] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["principal".to_smolstr()]);
    }

    #[test]
    fn entity_named_resource() {
        let src = r#"
        entity resource= {};
        entity Foo in [resource] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["resource".to_smolstr()]);
    }

    #[test]
    fn entity_named_action() {
        let src = r#"
        entity action= {};
        entity Foo in [action] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["action".to_smolstr()]);
    }

    #[test]
    fn entity_named_context() {
        let src = r#"
        entity context= {};
        entity Foo in [context] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["context".to_smolstr()]);
    }

    #[test]
    fn entity_named_attributes() {
        let src = r#"
        entity attributes= {};
        entity Foo in [attributes] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["attributes".to_smolstr()]);
    }

    #[test]
    fn entity_named_bool() {
        let src = r#"
        entity Bool= {};
        entity Foo in [Bool] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["Bool".to_smolstr()]);
    }

    #[test]
    fn entity_named_long() {
        let src = r#"
        entity Long= {};
        entity Foo in [Long] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["Long".to_smolstr()]);
    }

    #[test]
    fn entity_named_string() {
        let src = r#"
        entity String= {};
        entity Foo in [String] = {};
        "#;

        let (schema, _) = SchemaFragment::from_str_natural(src).unwrap();
        let ns = schema.0.get("").unwrap();
        let foo = ns.entity_types.get("Foo").unwrap();
        assert_eq!(foo.member_of_types, vec!["String".to_smolstr()]);
    }

    #[test]
    fn entity_named_if() {
        let src = r#"
        entity if = {};
        entity Foo in [if] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src).is_err());
    }

    #[test]
    fn entity_named_like() {
        let src = r#"
        entity like = {};
        entity Foo in [like] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src).is_err());
    }

    #[test]
    fn entity_named_true() {
        let src = r#"
        entity true = {};
        entity Foo in [true] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src).is_err());
    }

    #[test]
    fn entity_named_false() {
        let src = r#"
        entity false = {};
        entity Foo in [false] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src).is_err());
    }

    #[test]
    fn entity_named_has() {
        let src = r#"
        entity has = {};
        entity Foo in [has] = {};
        "#;

        assert!(SchemaFragment::from_str_natural(src).is_err());
    }
}
