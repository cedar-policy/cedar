#[cfg(test)]
mod tests {
    use crate::custom_schema::parser::parse_schema;

    #[test]
    fn test_trival() {
        let res = parse_schema(r#"entity User in [UserGroup,""];"#);
        assert!(res.is_err(), "{res:?}");
    }
}
