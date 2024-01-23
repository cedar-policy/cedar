#[cfg(test)]
mod demo_tests {
    use crate::custom_schema::parser::parse_schema;

    #[test]
    fn test_github() {
        let res = parse_schema(
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
        );
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn test_doc_cloud() {
        let res = parse_schema(
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
                isPrivate: Boolean,
                publicAccess: String,
                viewACL: DocumentShare,
                modifyACL: DocumentShare,
                manageACL: DocumentShare
            };
            entity DocumentShare;
            entity Public in [DocumentShare];
            entity Drive;
        }"#,
        );
        assert!(res.is_ok(), "{res:?}");
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

// PANIC CHECK: tests
#[allow(clippy::unreachable)]
#[cfg(test)]
mod translator_tests {
    use cedar_policy_core::FromNormalizedStr;

    use crate::{
        custom_schema::{
            err::ToJsonSchemaError, parser::parse_schema,
            to_json_schema::custom_schema_to_json_schema,
        },
        SchemaError, ValidatorSchema,
    };

    fn custom_schema_str_to_json_schema(
        s: &str,
    ) -> Result<crate::SchemaFragment, ToJsonSchemaError> {
        custom_schema_to_json_schema(parse_schema(s).expect("parse error")).map(|(sf, _)| sf)
    }

    #[test]
    fn use_reserved_namespace() {
        let schema = custom_schema_str_to_json_schema(
            r#"
          namespace __cedar {}
        "#,
        );
        assert!(
            schema.is_err()
                && matches!(
                    schema.unwrap_err(),
                    ToJsonSchemaError::UseReservedNamespace(_)
                ),
            "duplicate namespaces shouldn't be allowed"
        );
    }

    #[test]
    fn duplicate_namespace() {
        let schema = custom_schema_str_to_json_schema(
            r#"
          namespace A {}
          namespace A {}
        "#,
        );
        assert!(
            schema.is_err()
                && matches!(schema.unwrap_err(), ToJsonSchemaError::DuplicateNSIds(_, _)),
            "duplicate namespaces shouldn't be allowed"
        );
    }

    #[test]
    fn duplicate_action_types() {
        let schema = custom_schema_str_to_json_schema(
            r#"
          action A;
          action A appliesTo { context: {}};
        "#,
        );
        assert!(
            schema.is_err()
                && matches!(
                    schema.as_ref().unwrap_err(),
                    ToJsonSchemaError::DuplicateDeclarations(_, _)
                ),
            "duplicate action type names shouldn't be allowed: {schema:?}"
        );
        let schema = custom_schema_str_to_json_schema(
            r#"
          action A;
          action "A";
        "#,
        );
        assert!(
            schema.is_err()
                && matches!(
                    schema.as_ref().unwrap_err(),
                    ToJsonSchemaError::DuplicateDeclarations(_, _)
                ),
            "duplicate action type names shouldn't be allowed: {schema:?}"
        );
        let schema = custom_schema_str_to_json_schema(
            r#"
          namespace X { action A; }
          action A;
        "#,
        );
        assert!(schema.is_ok());
    }

    #[test]
    fn duplicate_entity_types() {
        let schema = custom_schema_str_to_json_schema(
            r#"
          entity A;
          entity A {};
        "#,
        );
        assert!(
            schema.is_err()
                && matches!(
                    schema.as_ref().unwrap_err(),
                    ToJsonSchemaError::DuplicateDeclarations(_, _)
                ),
            "duplicate entity type names shouldn't be allowed: {schema:?}"
        );
        let schema = custom_schema_str_to_json_schema(
            r#"
          namespace X { entity A; }
          entity A, A {};
        "#,
        );
        assert!(schema.is_ok());
    }

    #[test]
    fn duplicate_common_types() {
        let schema = custom_schema_str_to_json_schema(
            r#"
          type A = Bool;
          type A = Long;
        "#,
        );
        assert!(
            schema.is_err()
                && matches!(
                    schema.as_ref().unwrap_err(),
                    ToJsonSchemaError::DuplicateDeclarations(_, _)
                ),
            "duplicate common type names shouldn't be allowed: {schema:?}"
        );
        let schema = custom_schema_str_to_json_schema(
            r#"
          namespace X { type A = Bool; }
          type A = Long;
        "#,
        );
        assert!(schema.is_ok());
    }

    #[test]
    fn type_name_resolution_basic() {
        let schema = custom_schema_str_to_json_schema(
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
        );
        let validator_schema: ValidatorSchema = schema
            .expect("should be a valid custom schema")
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
        let schema = custom_schema_str_to_json_schema(
            r#"namespace A {
                entity B in [X::Y, A::C];
                entity C;
            }
            namespace X {
                entity Y;
            }
            "#,
        );
        let validator_schema: ValidatorSchema = schema
            .expect("should be a valid custom schema")
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
        let schema = custom_schema_str_to_json_schema(
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
        );
        let validator_schema: Result<ValidatorSchema, _> =
            schema.expect("should be a valid custom schema").try_into();
        assert!(validator_schema.is_err());
    }

    #[test]
    fn type_name_resolution_cross_namespace() {
        let schema = custom_schema_str_to_json_schema(
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
        );
        let validator_schema: ValidatorSchema = schema
            .expect("should be a valid custom schema")
            .try_into()
            .expect("should be a valid schema");
        let et = validator_schema
            .get_entity_type(&cedar_policy_core::ast::Name::from_normalized_str("A::B").unwrap())
            .unwrap();
        let attr = et.attr("foo").unwrap();
        assert!(
            matches!(&attr.attr_type, crate::types::Type::Primitive { primitive_type } if matches!(primitive_type, crate::types::Primitive::Bool))
        );

        let schema = custom_schema_str_to_json_schema(
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
        );
        let validator_schema: Result<ValidatorSchema, _> =
            schema.expect("should be a valid custom schema").try_into();
        assert!(
            validator_schema.is_err()
                && matches!(
                    validator_schema.unwrap_err(),
                    SchemaError::UndeclaredCommonTypes(_)
                )
        );
    }
}
