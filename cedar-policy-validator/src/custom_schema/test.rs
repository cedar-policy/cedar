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

#[cfg(test)]
mod translator_tests {
    use crate::custom_schema::{err::ToJsonSchemaError, parser::parse_schema};

    fn custom_schema_str_to_json_schema(
        s: &str,
    ) -> Result<crate::SchemaFragment, ToJsonSchemaError> {
        parse_schema(s).expect("parse error").try_into()
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
            schema.is_err() && matches!(schema.unwrap_err(), ToJsonSchemaError::DuplicateNSIds(_)),
            "duplicate namespaces shouldn't be allowed"
        );
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
                    ToJsonSchemaError::DuplicateKeys(_, _)
                ),
            "duplicate entity type names shouldn't be allowed: {schema:?}"
        );
    }
}
