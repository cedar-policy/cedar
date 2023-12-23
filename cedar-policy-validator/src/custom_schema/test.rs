#[cfg(test)]
mod tests {
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
