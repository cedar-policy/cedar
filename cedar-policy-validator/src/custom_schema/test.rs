#[cfg(test)]
mod demo_tests {

    use smol_str::ToSmolStr;

    use crate::{
        custom_schema::parser::parse_schema, EntityType, SchemaFragment, SchemaTypeVariant, TypeOfAttribute,
    };

    #[test]
    fn test_github() {
        let (fragment, _warnings) = SchemaFragment::from_str_natural(
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
        let _repo = github
            .entity_types
            .get("Repository")
            .expect("No `Repository`");
        assert!(repo.member_of_types.is_empty());
        let groups = ["readers", "writers", "triagers", "admins", "maintainers"];
<<<<<<< HEAD
        for _group in groups {}
=======
        for group in groups {
            match &repo.shape.0 { 
                crate::SchemaType::Type(SchemaTypeVariant::Record { 
                    attributes, additional_attributes : false,
                }) => { 
                    let expected = SchemaTypeVariant::Entity { name : "UserGroup".into() };
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
                attributes, additional_attributes : false
            }) => { 
                let attribute = attributes.get("repo").expect("No `repo`");
                assert_has_type(attribute, SchemaTypeVariant::Entity { name : "Repository".into() });
                let attribute = attributes.get("reporter").expect("No `repo`");
                assert_has_type(attribute, SchemaTypeVariant::Entity { name : "User".into() });
            }
            _ => panic!("bad type on `Issue`"),
        }
        let org = github.entity_types.get("Org").expect("No `Org`");
        assert!(org.member_of_types.is_empty());
        let groups = ["members", "owners", "memberOfTypes" ];
        for group in groups {
            match &org.shape.0 { 
                crate::SchemaType::Type(SchemaTypeVariant::Record { 
                    attributes, additional_attributes : false,
                }) => { 
                    let expected = SchemaTypeVariant::Entity { name : "UserGroup".into() };
                    let attribute = attributes.get(group).expect("No attribute `{group}`");
                    assert_has_type(attribute, expected);
                }
                _ => panic!("Shape was not a record"),
            }
        }
    }

    fn assert_has_type(e : &TypeOfAttribute, expected : SchemaTypeVariant) {
        assert!(e.required, "Attribute was not required");
        match &e.ty { 
            crate::SchemaType::Type(t) => assert_eq!(t, &expected),
            _ => panic!("Wrong type"),
        }
>>>>>>> 6bba1881 (WIP)
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
        ).expect("failed to parse");
        assert!(warnings.collect::<Vec<_>>().is_empty());
        let doccloud = fragment.0.get("DocCloud").expect("No `DocCloud` namespace");
        let user = doccloud.entity_types.get("User").expect("No `User`");
        assert_eq!(&user.member_of_types,&vec!["Group".to_smolstr()]);
        match &user.shape.0 { 
            crate::SchemaType::Type(SchemaTypeVariant::Record { attributes, additional_attributes : false }) => { 
                assert_has_type(
                    attributes.get("personalGroup").unwrap(), SchemaTypeVariant::Entity { name : "Group".into() });
                assert_has_type(
                    attributes.get("blocked").unwrap(), SchemaTypeVariant::Set { element : Box::new(crate::SchemaType::Type(SchemaTypeVariant::Entity { name : "User".into() })) });
            }, 
            _ => panic!("Wrong type"),
        }
        let group = doccloud.entity_types.get("Group").expect("No `Group`");
        assert_eq!(&group.member_of_types,&vec!["DocumentShare".to_smolstr()]);
        match &group.shape.0 { 
            crate::SchemaType::Type(SchemaTypeVariant::Record { attributes, additional_attributes : false }) => { 
                assert_has_type(
                    attributes.get("owner").unwrap(), SchemaTypeVariant::Entity { name : "User".into() });
            }, 
            _ => panic!("Wrong type"),
        }
        let document = doccloud.entity_types.get("Document").expect("No `Group`");
        assert!(document.member_of_types.is_empty());
        match &document.shape.0 { 
            crate::SchemaType::Type(SchemaTypeVariant::Record { attributes, additional_attributes : false }) => { 
                assert_has_type(
                    attributes.get("owner").unwrap(), SchemaTypeVariant::Entity { name : "User".into() });
                assert_has_type(
                    attributes.get("isPrivate").unwrap(), SchemaTypeVariant::Boolean);
                assert_has_type(
                    attributes.get("publicAccess").unwrap(), SchemaTypeVariant::String);
                assert_has_type(
                    attributes.get("viewACL").unwrap(), SchemaTypeVariant::Entity { name : "DocumentShare".into() });
                assert_has_type(
                    attributes.get("modifyACL").unwrap(), SchemaTypeVariant::Entity { name : "DocumentShare".into() });
                assert_has_type(
                    attributes.get("manageACL").unwrap(), SchemaTypeVariant::Entity { name : "DocumentShare".into() });
            }, 
            _ => panic!("Wrong type"),
        }
        let document_share = doccloud.entity_types.get("DocumentShare").expect("No `DocumentShare`");
        assert!(document_share.member_of_types.is_empty());
        assert_empty_records(document_share);

        let public = doccloud.entity_types.get("Public").expect("No `Public`");
        assert_eq!(&public.member_of_types,&vec!["DocumentShare".to_smolstr()]);
        assert_empty_records(public);

        let drive = doccloud.entity_types.get("Drive").expect("No `Drive`");
        assert!(drive.member_of_types.is_empty());
        assert_empty_records(drive);

    }
}

#[cfg(test)]
mod parser_tests {
    use crate::custom_schema::parser::parse_schema;

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
#[cfg(test)]
mod translator_tests {
    use cedar_policy_core::FromNormalizedStr;

<<<<<<< HEAD
    use crate::{custom_schema::err::ToJsonSchemaError, SchemaError, ValidatorSchema};

    fn custom_schema_str_to_json_schema(
        _s: &str,
    ) -> Result<crate::SchemaFragment, ToJsonSchemaError> {
        todo!()
        // custom_schema_to_json_schema(parse_schema(s).expect("parse error")).map(|(sf, _)| sf)
    }
=======
    use crate::{
        SchemaFragment,
        custom_schema::{
            err::ToJsonSchemaError, parser::parse_schema,
            to_json_schema::custom_schema_to_json_schema,
        },
        SchemaError, ValidatorSchema,
    };

>>>>>>> 6bba1881 (WIP)

    #[test]
    fn use_reserved_namespace() {
        let schema = SchemaFragment::from_str_natural(
            r#"
          namespace __cedar {}
        "#,
        );
        assert!(
            schema.is_err(),
            "duplicate namespaces shouldn't be allowed"
        );
    }

    #[test]
    fn duplicate_namespace() {
        let schema = SchemaFragment::from_str_natural(
            r#"
          namespace A {}
          namespace A {}
        "#,
        );
        assert!(
            schema.is_err(),
            "duplicate namespaces shouldn't be allowed"
        );
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
          namespace X { entity A; }
          entity A, A {};
        "#,
        ).is_ok());
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
        ).is_ok());
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
            .expect("should be a valid custom schema");
        let validator_schema: ValidatorSchema = schema
            .try_into()
            .expect("should be a valid schema");
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
        ).unwrap();
        let validator_schema: ValidatorSchema = schema
            .try_into()
            .expect("should be a valid schema");
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
            r#"type id = {
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
        ).unwrap();
        let validator_schema: Result<ValidatorSchema, _> =
            schema.try_into();
        assert!(validator_schema.is_err());
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
        ).unwrap();
        let validator_schema: ValidatorSchema = schema
            .try_into()
            .expect("should be a valid schema");
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
        ).unwrap();
        let validator_schema: Result<ValidatorSchema, _> =
            schema.try_into();
        assert!(
            validator_schema.is_err()
                && matches!(
                    validator_schema.unwrap_err(),
                    SchemaError::UndeclaredCommonTypes(_)
                )
        );
    }
}
