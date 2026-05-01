#[cfg(test)]
mod partial_eval_test_utils {
    use std::collections::HashSet;
    use std::sync::Arc;

    use crate::ast::{Eid, EntityUID, Literal};
    use crate::parser::parse_policyset;
    use crate::tpe::entities::{PartialEntities, PartialEntity};
    use crate::tpe::request::{PartialEntityUID, PartialRequest};
    use crate::tpe::residual::Residual;

    /// Assert that evaluating `$residual` produces the expected Cedar string.
    /// Usage: `check!($residual, "expected cedar string")`
    macro_rules! check {
        ($residual:expr, $expected:expr) => {
            assert_eq!(
                $crate::tpe::partial_eval_tests::partial_eval_test_utils::to_cedar(&$residual),
                $expected
            )
        };
    }
    use crate::tpe::value::{PartialAttribute, PartialRecord, PartialValue};
    use crate::validator::ValidatorSchema;
    pub(crate) use check;
    use smol_str::SmolStr;

    pub fn uid(ty: &str, id: &str) -> EntityUID {
        EntityUID::from_components(ty.parse().unwrap(), Eid::new(id), None)
    }

    pub fn request(
        principal_ty: &str,
        principal_id: Option<&str>,
        action_id: &str,
        resource_ty: &str,
        resource_id: Option<&str>,
    ) -> PartialRequest {
        PartialRequest {
            principal: PartialEntityUID {
                ty: principal_ty.parse().unwrap(),
                eid: principal_id.map(Eid::new),
            },
            action: uid("Action", action_id),
            resource: PartialEntityUID {
                ty: resource_ty.parse().unwrap(),
                eid: resource_id.map(Eid::new),
            },
            context: Some(PartialRecord::new()),
        }
    }

    pub fn entity(
        ty: &str,
        id: &str,
        attrs: Option<PartialRecord>,
        tags: Option<PartialRecord>,
    ) -> (EntityUID, PartialEntity) {
        let u = uid(ty, id);
        (
            u.clone(),
            PartialEntity {
                uid: u,
                attrs,
                ancestors: Some(HashSet::new()),
                tags,
            },
        )
    }

    pub fn eval_residual(
        schema: &ValidatorSchema,
        req: &PartialRequest,
        entities: impl Iterator<Item = (EntityUID, PartialEntity)>,
        policy: &str,
    ) -> Residual {
        let policies = parse_policyset(policy).unwrap();
        let ents = PartialEntities::from_entities_unchecked(entities);
        let response = crate::tpe::is_authorized(&policies, req, &ents, schema).unwrap();
        let id = policies.static_policies().next().unwrap().id().clone();
        response
            .get_residual_policy(&id)
            .unwrap()
            .get_residual()
            .as_ref()
            .clone()
    }

    pub fn to_cedar(r: &Residual) -> String {
        let expr: crate::ast::Expr = r.clone().into();
        expr.to_string()
    }

    pub fn present(v: impl Into<Literal>) -> PartialAttribute {
        PartialAttribute::Present(PartialValue::Lit(v.into()))
    }

    pub fn present_uid(ty: &str, id: &str) -> PartialAttribute {
        PartialAttribute::Present(PartialValue::Lit(Literal::EntityUID(Arc::new(uid(ty, id)))))
    }

    pub fn record(
        fields: impl IntoIterator<Item = (impl Into<SmolStr>, PartialAttribute)>,
    ) -> PartialAttribute {
        PartialAttribute::Present(PartialValue::Record(PartialRecord::from_attrs(
            fields.into_iter().map(|(k, v)| (k.into(), v)),
        )))
    }

    pub fn rec(
        fields: impl IntoIterator<Item = (impl Into<SmolStr>, PartialAttribute)>,
    ) -> PartialRecord {
        PartialRecord::from_attrs(fields.into_iter().map(|(k, v)| (k.into(), v)))
    }
}

#[cfg(test)]
mod partial_attr_tests {
    use super::partial_eval_test_utils::*;
    use crate::extensions::Extensions;
    use crate::tpe::residual::Residual;
    use crate::tpe::value::{PartialAttribute as PA, PartialRecord};
    use crate::validator::ValidatorSchema;
    use cool_asserts::assert_matches;
    use rstest::rstest;

    fn setup() -> (ValidatorSchema, crate::tpe::request::PartialRequest) {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"
            entity User { name: String, level: Long } tags String;
            entity Document { owner: User, public: Bool };
            action Read appliesTo { principal: User, resource: Document, context: {} };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        (
            schema,
            request("User", Some("alice"), "Read", "Document", Some("doc")),
        )
    }

    fn eval(public_attr: PA, policy: &str) -> Residual {
        let (schema, req) = setup();
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "Document",
                    "doc",
                    Some(rec([
                        ("owner", present_uid("User", "alice")),
                        ("public", public_attr),
                    ])),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "User",
                    "alice",
                    Some(rec([("name", present("Alice")), ("level", present(5))])),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    fn eval_no_public(policy: &str) -> Residual {
        let (schema, req) = setup();
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "Document",
                    "doc",
                    Some(rec([("owner", present_uid("User", "alice"))])),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "User",
                    "alice",
                    Some(rec([("name", present("Alice")), ("level", present(5))])),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    fn eval_tag(tag_attr: PA, policy: &str) -> Residual {
        let (schema, req) = setup();
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "Document",
                    "doc",
                    Some(rec([
                        ("owner", present_uid("User", "alice")),
                        ("public", present(true)),
                    ])),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "User",
                    "alice",
                    Some(rec([("name", present("Alice")), ("level", present(5))])),
                    Some(rec([("role", tag_attr)])),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    fn eval_no_tags(policy: &str) -> Residual {
        let (schema, req) = setup();
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "Document",
                    "doc",
                    Some(rec([
                        ("owner", present_uid("User", "alice")),
                        ("public", present(true)),
                    ])),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "User",
                    "alice",
                    Some(rec([("name", present("Alice")), ("level", present(5))])),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    // policy: resource.public
    #[rstest]
    #[case::present(present(true), "true")]
    #[case::unknown(PA::Unknown, r#"Document::"doc".public"#)]
    fn get_attr(#[case] public: PA, #[case] expected: &str) {
        check!(
            eval(
                public,
                r#"@id("p") permit(principal,action,resource) when { resource.public };"#
            ),
            expected
        );
    }

    #[test]
    fn get_absent_is_error() {
        assert_matches!(
            eval(
                PA::Absent,
                r#"@id("p") permit(principal,action,resource) when { resource.public };"#
            ),
            Residual::Error(_)
        );
    }

    #[test]
    fn get_not_in_map() {
        check!(
            eval_no_public(
                r#"@id("p") permit(principal,action,resource) when { resource.public };"#
            ),
            r#"Document::"doc".public"#
        );
    }

    // policy: resource has public && resource.public
    #[rstest]
    #[case::present(present(true), "true")]
    #[case::unknown(PA::Unknown, r#"Document::"doc".public"#)]
    #[case::absent(PA::Absent, "false")]
    fn has_and_get_attr(#[case] public: PA, #[case] expected: &str) {
        check!(
            eval(
                public,
                r#"@id("p") permit(principal,action,resource) when { resource has public && resource.public };"#
            ),
            expected
        );
    }

    #[test]
    fn has_and_get_not_in_map() {
        check!(
            eval_no_public(
                r#"@id("p") permit(principal,action,resource) when { resource has public && resource.public };"#
            ),
            r#"(Document::"doc" has public) && (Document::"doc".public)"#
        );
    }

    // policy: resource has public (has-only, no access)
    #[rstest]
    #[case::present(present(true), "true")]
    #[case::unknown(PA::Unknown, "true")]
    #[case::absent(PA::Absent, "false")]
    fn has_only(#[case] public: PA, #[case] expected: &str) {
        check!(
            eval(
                public,
                r#"@id("p") permit(principal,action,resource) when { resource has public };"#
            ),
            expected
        );
    }

    #[test]
    fn has_only_not_in_map() {
        check!(
            eval_no_public(
                r#"@id("p") permit(principal,action,resource) when { resource has public };"#
            ),
            r#"Document::"doc" has public"#
        );
    }

    // policy: resource.owner == principal && resource.public
    #[test]
    fn mixed_present_and_unknown() {
        check!(
            eval(
                PA::Unknown,
                r#"@id("p") permit(principal,action,resource) when { resource.owner == principal && resource.public };"#
            ),
            r#"Document::"doc".public"#
        );
    }

    // policy: principal.hasTag("role") && principal.getTag("role") == "admin"
    #[rstest]
    #[case::present(present("admin"), "true")]
    #[case::unknown(PA::Unknown, r#"(User::"alice".getTag("role")) == "admin""#)]
    #[case::absent(PA::Absent, "false")]
    fn tag_has_and_get(#[case] attr: PA, #[case] expected: &str) {
        check!(
            eval_tag(
                attr,
                r#"@id("p") permit(principal,action,resource) when { principal.hasTag("role") && principal.getTag("role") == "admin" };"#
            ),
            expected
        );
    }

    #[test]
    fn tag_has_and_get_not_in_map() {
        check!(
            eval_no_tags(
                r#"@id("p") permit(principal,action,resource) when { principal.hasTag("role") && principal.getTag("role") == "admin" };"#
            ),
            r#"(User::"alice".hasTag("role")) && ((User::"alice".getTag("role")) == "admin")"#
        );
    }

    // policy: principal.hasTag("role") (hasTag-only)
    #[rstest]
    #[case::present(present("admin"), "true")]
    #[case::unknown(PA::Unknown, "true")]
    #[case::absent(PA::Absent, "false")]
    fn tag_has_only(#[case] attr: PA, #[case] expected: &str) {
        check!(
            eval_tag(
                attr,
                r#"@id("p") permit(principal,action,resource) when { principal.hasTag("role") };"#
            ),
            expected
        );
    }

    #[test]
    fn tag_has_only_not_in_map() {
        check!(
            eval_no_tags(
                r#"@id("p") permit(principal,action,resource) when { principal.hasTag("role") };"#
            ),
            r#"User::"alice".hasTag("role")"#
        );
    }
}

#[cfg(test)]
mod nested_partial_attr_tests {
    use super::partial_eval_test_utils::*;
    use crate::extensions::Extensions;
    use crate::tpe::value::{PartialAttribute as PA, PartialRecord};
    use crate::validator::ValidatorSchema;
    use rstest::rstest;

    fn setup() -> (ValidatorSchema, crate::tpe::request::PartialRequest) {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"
            entity User;
            entity Document { meta: { title: String, rating: Long }, public: Bool };
            action Read appliesTo { principal: User, resource: Document, context: {} };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        (
            schema,
            request("User", Some("alice"), "Read", "Document", Some("doc")),
        )
    }

    fn eval(meta: PA, policy: &str) -> crate::tpe::residual::Residual {
        let (schema, req) = setup();
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "Document",
                    "doc",
                    Some(rec([("meta", meta), ("public", present(true))])),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "User",
                    "alice",
                    Some(PartialRecord::new()),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    // policy: resource.meta.title == "My Doc"
    #[rstest]
    #[case::all_present(   record([("title", present("My Doc")), ("rating", present(5))]),  "true")]
    #[case::unknown_field( record([("title", PA::Unknown), ("rating", present(5))]),         r#"((Document::"doc".meta).title) == "My Doc""#)]
    #[case::absent_field(  record([("title", PA::Absent), ("rating", present(5))]),          "error()")]
    #[case::entire_unknown(PA::Unknown, r#"((Document::"doc".meta).title) == "My Doc""#)]
    #[case::not_in_map(    record([("rating", present(5))]),                                 r#"((Document::"doc".meta).title) == "My Doc""#)]
    fn title_eq(#[case] meta: PA, #[case] expected: &str) {
        check!(
            eval(
                meta,
                r#"@id("p") permit(principal,action,resource) when { resource.meta.title == "My Doc" };"#
            ),
            expected
        );
    }

    // policy: resource.meta has title (has on nested required field)
    #[rstest]
    #[case::present(       record([("title", present("Doc")), ("rating", present(5))]),  "true")]
    #[case::unknown(       record([("title", PA::Unknown), ("rating", present(5))]),      "true")]
    #[case::absent(        record([("title", PA::Absent), ("rating", present(5))]),       "false")]
    #[case::entire_unknown(PA::Unknown, r#"(Document::"doc".meta) has title"#)]
    #[case::not_in_map(    record([("rating", present(5))]),                              "true")]
    fn has_title(#[case] meta: PA, #[case] expected: &str) {
        check!(
            eval(
                meta,
                r#"@id("p") permit(principal,action,resource) when { resource.meta has title };"#
            ),
            expected
        );
    }

    // policy: resource.meta.rating > 3 && resource.meta.title == "My Doc"
    #[test]
    fn mixed_known_and_unknown_fields() {
        check!(
            eval(
                record([("title", PA::Unknown), ("rating", present(5))]),
                r#"@id("p") permit(principal,action,resource) when { resource.meta.rating > 3 && resource.meta.title == "My Doc" };"#
            ),
            r#"((Document::"doc".meta).title) == "My Doc""#
        );
    }

    // policy: resource.meta == {title: "My Doc", rating: 5}
    #[test]
    fn record_equality() {
        check!(
            eval(
                record([("title", PA::Unknown), ("rating", present(5))]),
                r#"@id("p") permit(principal,action,resource) when { resource.meta == {title: "My Doc", rating: 5} };"#
            ),
            r#"{rating: 5, title: (Document::"doc".meta).title} == {rating: 5, title: "My Doc"}"#
        );
    }
}

#[cfg(test)]
mod partial_record_tag_tests {
    use super::partial_eval_test_utils::*;
    use crate::extensions::Extensions;
    use crate::tpe::value::{PartialAttribute as PA, PartialRecord};
    use crate::validator::ValidatorSchema;
    use rstest::rstest;

    fn setup() -> (ValidatorSchema, crate::tpe::request::PartialRequest) {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"
            entity User tags { role: String, level: Long };
            entity Document;
            action Read appliesTo { principal: User, resource: Document, context: {} };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        (
            schema,
            request("User", Some("alice"), "Read", "Document", Some("doc")),
        )
    }

    fn eval(tag: &str, val: PA, policy: &str) -> crate::tpe::residual::Residual {
        let (schema, req) = setup();
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "User",
                    "alice",
                    Some(PartialRecord::new()),
                    Some(rec([(tag, val)])),
                ),
                entity(
                    "Document",
                    "doc",
                    Some(PartialRecord::new()),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    // policy: principal.hasTag("info") && principal.getTag("info").role == "admin"
    #[rstest]
    #[case::all_present(   record([("role", present("admin")), ("level", present(5))]),  "true")]
    #[case::unknown_field( record([("role", PA::Unknown), ("level", present(5))]),        r#"((User::"alice".getTag("info")).role) == "admin""#)]
    #[case::not_in_map(    record([("level", present(5))]),                               r#"((User::"alice".getTag("info")).role) == "admin""#)]
    fn get_role(#[case] val: PA, #[case] expected: &str) {
        check!(
            eval(
                "info",
                val,
                r#"@id("p") permit(principal,action,resource) when { principal.hasTag("info") && principal.getTag("info").role == "admin" };"#
            ),
            expected
        );
    }

    // policy: principal.hasTag("info") && principal.getTag("info").level > 3
    #[test]
    fn known_sibling_resolves() {
        check!(
            eval(
                "info",
                record([("role", PA::Unknown), ("level", present(5))]),
                r#"@id("p") permit(principal,action,resource) when { principal.hasTag("info") && principal.getTag("info").level > 3 };"#
            ),
            "true"
        );
    }
}

#[cfg(test)]
mod optional_attr_tests {
    use super::partial_eval_test_utils::*;
    use crate::extensions::Extensions;
    use crate::tpe::value::{PartialAttribute as PA, PartialRecord};
    use crate::validator::ValidatorSchema;
    use rstest::rstest;

    fn setup() -> (ValidatorSchema, crate::tpe::request::PartialRequest) {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"
            entity User { name: String, nickname?: String };
            entity Document;
            action Read appliesTo { principal: User, resource: Document, context: {} };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        (
            schema,
            request("User", Some("alice"), "Read", "Document", Some("doc")),
        )
    }

    fn eval(nickname: PA, policy: &str) -> crate::tpe::residual::Residual {
        let (schema, req) = setup();
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "User",
                    "alice",
                    Some(rec([("name", present("Alice")), ("nickname", nickname)])),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "Document",
                    "doc",
                    Some(PartialRecord::new()),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    fn eval_no_nickname(policy: &str) -> crate::tpe::residual::Residual {
        let (schema, req) = setup();
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "User",
                    "alice",
                    Some(rec([("name", present("Alice"))])),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "Document",
                    "doc",
                    Some(PartialRecord::new()),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    // policy: principal has nickname
    #[rstest]
    #[case::unknown(PA::Unknown, "true")]
    #[case::absent(PA::Absent, "false")]
    #[case::present(present("Ali"), "true")]
    fn has(#[case] nickname: PA, #[case] expected: &str) {
        check!(
            eval(
                nickname,
                r#"@id("p") permit(principal,action,resource) when { principal has nickname };"#
            ),
            expected
        );
    }

    #[test]
    fn has_not_in_map() {
        check!(
            eval_no_nickname(
                r#"@id("p") permit(principal,action,resource) when { principal has nickname };"#
            ),
            r#"User::"alice" has nickname"#
        );
    }

    // policy: principal has nickname && principal.nickname == "Ali"
    #[rstest]
    #[case::unknown(PA::Unknown, r#"(User::"alice".nickname) == "Ali""#)]
    #[case::absent(PA::Absent, "false")]
    #[case::present(present("Ali"), "true")]
    fn guarded(#[case] nickname: PA, #[case] expected: &str) {
        check!(
            eval(
                nickname,
                r#"@id("p") permit(principal,action,resource) when { principal has nickname && principal.nickname == "Ali" };"#
            ),
            expected
        );
    }

    #[test]
    fn guarded_not_in_map() {
        check!(
            eval_no_nickname(
                r#"@id("p") permit(principal,action,resource) when { principal has nickname && principal.nickname == "Ali" };"#
            ),
            r#"(User::"alice" has nickname) && ((User::"alice".nickname) == "Ali")"#
        );
    }
}

#[cfg(test)]
mod nested_optional_attr_tests {
    use super::partial_eval_test_utils::*;
    use crate::extensions::Extensions;
    use crate::tpe::value::{PartialAttribute as PA, PartialRecord};
    use crate::validator::ValidatorSchema;
    use rstest::rstest;

    fn setup() -> (ValidatorSchema, crate::tpe::request::PartialRequest) {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"
            entity User;
            entity Document { meta: { title: String, subtitle?: String } };
            action Read appliesTo { principal: User, resource: Document, context: {} };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        (
            schema,
            request("User", Some("alice"), "Read", "Document", Some("doc")),
        )
    }

    fn eval(meta: PA, policy: &str) -> crate::tpe::residual::Residual {
        let (schema, req) = setup();
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "Document",
                    "doc",
                    Some(rec([("meta", meta)])),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "User",
                    "alice",
                    Some(PartialRecord::new()),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    // policy: resource.meta has subtitle
    #[rstest]
    #[case::present(    record([("title", present("Doc")), ("subtitle", present("Sub"))]),  "true")]
    #[case::unknown(    record([("title", present("Doc")), ("subtitle", PA::Unknown)]),     "true")]
    #[case::not_in_map( record([("title", present("Doc"))]),                                r#"(Document::"doc".meta) has subtitle"#)]
    #[case::absent(     record([("title", present("Doc")), ("subtitle", PA::Absent)]),      "false")]
    fn has_subtitle(#[case] meta: PA, #[case] expected: &str) {
        check!(
            eval(
                meta,
                r#"@id("p") permit(principal,action,resource) when { resource.meta has subtitle };"#
            ),
            expected
        );
    }

    // policy: resource.meta has subtitle && resource.meta.subtitle == "Sub"
    #[rstest]
    #[case::unknown(    record([("title", present("Doc")), ("subtitle", PA::Unknown)]),    r#"((Document::"doc".meta).subtitle) == "Sub""#)]
    #[case::not_in_map( record([("title", present("Doc"))]),                                r#"((Document::"doc".meta) has subtitle) && (((Document::"doc".meta).subtitle) == "Sub")"#)]
    #[case::absent(     record([("title", present("Doc")), ("subtitle", PA::Absent)]),      "false")]
    #[case::present(    record([("title", present("Doc")), ("subtitle", present("Sub"))]),  "true")]
    fn guarded_subtitle(#[case] meta: PA, #[case] expected: &str) {
        check!(
            eval(
                meta,
                r#"@id("p") permit(principal,action,resource) when { resource.meta has subtitle && resource.meta.subtitle == "Sub" };"#
            ),
            expected
        );
    }
}

#[cfg(test)]
mod context_tests {
    use super::partial_eval_test_utils::*;
    use crate::extensions::Extensions;
    use crate::tpe::request::PartialRequest;
    use crate::tpe::value::PartialRecord;
    use crate::validator::ValidatorSchema;

    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            r#"
            entity User;
            entity Document;
            action Read appliesTo {
                principal: User,
                resource: Document,
                context: { level: Long, tag?: String }
            };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn eval_ctx(context: Option<PartialRecord>, policy: &str) -> crate::tpe::residual::Residual {
        let sch = schema();
        let req = PartialRequest {
            principal: crate::tpe::request::PartialEntityUID {
                ty: "User".parse().unwrap(),
                eid: Some(crate::ast::Eid::new("alice")),
            },
            action: uid("Action", "Read"),
            resource: crate::tpe::request::PartialEntityUID {
                ty: "Document".parse().unwrap(),
                eid: Some(crate::ast::Eid::new("doc")),
            },
            context,
        };
        eval_residual(
            &sch,
            &req,
            [
                entity(
                    "User",
                    "alice",
                    Some(PartialRecord::new()),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "Document",
                    "doc",
                    Some(PartialRecord::new()),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    fn known_ctx(
        pairs: impl IntoIterator<Item = (&'static str, crate::ast::Literal)>,
    ) -> Option<PartialRecord> {
        use crate::tpe::value::{PartialAttribute, PartialValue};
        Some(rec(pairs.into_iter().map(|(k, v)| {
            (k, PartialAttribute::Present(PartialValue::Lit(v)))
        })))
    }

    #[test]
    fn context_known_attr() {
        check!(
            eval_ctx(
                known_ctx([("level", 5.into())]),
                r#"@id("p") permit(principal,action,resource) when { context.level > 3 };"#
            ),
            "true"
        );
    }

    #[test]
    fn context_entirely_unknown() {
        check!(
            eval_ctx(
                None,
                r#"@id("p") permit(principal,action,resource) when { context.level > 3 };"#
            ),
            "!((context.level) <= 3)"
        );
    }

    // policy: context has tag && context.tag == "admin"
    #[test]
    fn context_known_optional_present() {
        check!(
            eval_ctx(
                known_ctx([("level", 5.into()), ("tag", "admin".into())]),
                r#"@id("p") permit(principal,action,resource) when { context has tag && context.tag == "admin" };"#
            ),
            "true"
        );
    }

    #[test]
    fn context_known_optional_missing() {
        use crate::tpe::value::PartialAttribute as PA;
        check!(
            eval_ctx(
                partial_ctx([("level", present(5)), ("tag", PA::Absent)]),
                r#"@id("p") permit(principal,action,resource) when { context has tag && context.tag == "admin" };"#
            ),
            "false"
        );
    }

    #[test]
    fn context_unknown_optional() {
        check!(
            eval_ctx(
                None,
                r#"@id("p") permit(principal,action,resource) when { context has tag && context.tag == "admin" };"#
            ),
            r#"(context has tag) && ((context.tag) == "admin")"#
        );
    }

    // --- Partial context: per-field unknowns ---

    fn partial_ctx(
        fields: impl IntoIterator<Item = (&'static str, crate::tpe::value::PartialAttribute)>,
    ) -> Option<PartialRecord> {
        Some(rec(fields))
    }

    // policy: context.level > 3 — with level unknown
    #[test]
    fn partial_context_unknown_required() {
        use crate::tpe::value::PartialAttribute as PA;
        check!(
            eval_ctx(
                partial_ctx([("level", PA::Unknown)]),
                r#"@id("p") permit(principal,action,resource) when { context.level > 3 };"#
            ),
            "!((context.level) <= 3)"
        );
    }

    // policy: context.level > 3 — with level known
    #[test]
    fn partial_context_known_required() {
        check!(
            eval_ctx(
                partial_ctx([("level", present(5))]),
                r#"@id("p") permit(principal,action,resource) when { context.level > 3 };"#
            ),
            "true"
        );
    }

    // policy: context has tag && context.tag == "admin" — tag unknown (exists, value unknown)
    #[test]
    fn partial_context_unknown_optional() {
        use crate::tpe::value::PartialAttribute as PA;
        check!(
            eval_ctx(
                partial_ctx([("level", present(5)), ("tag", PA::Unknown)]),
                r#"@id("p") permit(principal,action,resource) when { context has tag && context.tag == "admin" };"#
            ),
            r#"(context.tag) == "admin""#
        );
    }

    // policy: context has tag && context.tag == "admin" — tag absent
    #[test]
    fn partial_context_absent_optional() {
        use crate::tpe::value::PartialAttribute as PA;
        check!(
            eval_ctx(
                partial_ctx([("level", present(5)), ("tag", PA::Absent)]),
                r#"@id("p") permit(principal,action,resource) when { context has tag && context.tag == "admin" };"#
            ),
            "false"
        );
    }

    // policy: context has tag && context.tag == "admin" — tag not in map (optional, might not exist)
    #[test]
    fn partial_context_not_in_map_optional() {
        check!(
            eval_ctx(
                partial_ctx([("level", present(5))]),
                r#"@id("p") permit(principal,action,resource) when { context has tag && context.tag == "admin" };"#
            ),
            r#"(context has tag) && ((context.tag) == "admin")"#
        );
    }
}

#[cfg(test)]
mod required_attr_not_in_map_tests {
    use super::partial_eval_test_utils::*;
    use crate::extensions::Extensions;
    use crate::tpe::value::{PartialAttribute as PA, PartialRecord};
    use crate::validator::ValidatorSchema;
    use rstest::rstest;

    fn setup() -> (ValidatorSchema, crate::tpe::request::PartialRequest) {
        let schema = ValidatorSchema::from_cedarschema_str(
            r#"
            entity User { name: String, nickname?: String };
            entity Document;
            action Read appliesTo { principal: User, resource: Document, context: {} };
            "#,
            Extensions::all_available(),
        )
        .unwrap()
        .0;
        (
            schema,
            request("User", Some("alice"), "Read", "Document", Some("doc")),
        )
    }

    /// Evaluate with a User entity that has only the specified attrs in its PartialRecord.
    /// Attrs not listed are simply not in the map initially. Required attrs not in the map
    /// are filled as `Unknown` (mimicking what `PartialEntity::new` does with schema knowledge).
    fn eval_with_attrs(
        attrs: impl IntoIterator<Item = (&'static str, PA)>,
        policy: &str,
    ) -> crate::tpe::residual::Residual {
        let (schema, req) = setup();
        let entity_type = schema.get_entity_type(&"User".parse().unwrap()).unwrap();
        let attrs_type = crate::validator::types::Type::Record {
            attrs: entity_type.attributes().clone(),
            open_attributes: entity_type.open_attributes(),
        };
        let mut user_attrs = rec(attrs);
        user_attrs.fill_required_attrs(&attrs_type);
        eval_residual(
            &schema,
            &req,
            [
                entity(
                    "User",
                    "alice",
                    Some(user_attrs),
                    Some(PartialRecord::new()),
                ),
                entity(
                    "Document",
                    "doc",
                    Some(PartialRecord::new()),
                    Some(PartialRecord::new()),
                ),
            ]
            .into_iter(),
            policy,
        )
    }

    // --- Required attr "name" not in map ---
    // Schema guarantees "name" exists, so `has` should be true and `get` should be residual.

    #[test]
    fn has_required_not_in_map() {
        check!(
            eval_with_attrs(
                [],
                r#"@id("p") permit(principal,action,resource) when { principal has name };"#
            ),
            "true"
        );
    }

    #[test]
    fn get_required_not_in_map() {
        check!(
            eval_with_attrs(
                [],
                r#"@id("p") permit(principal,action,resource) when { principal.name == "Alice" };"#
            ),
            r#"(User::"alice".name) == "Alice""#
        );
    }

    // --- Optional attr "nickname" not in map ---
    // Schema says nickname is optional, so existence is unknown → residual.

    #[test]
    fn has_optional_not_in_map() {
        check!(
            eval_with_attrs(
                [("name", present("Alice"))],
                r#"@id("p") permit(principal,action,resource) when { principal has nickname };"#
            ),
            r#"User::"alice" has nickname"#
        );
    }

    // Unguarded access to an optional attr is invalid Cedar (unsafe optional attribute access),
    // so we only test guarded access for optional not-in-map (see has_and_get_optional_not_in_map).

    // --- Guarded access: has && get on required not-in-map ---
    // `has` is true (required), so the guard passes and `get` produces a residual.

    #[test]
    fn has_and_get_required_not_in_map() {
        check!(
            eval_with_attrs(
                [],
                r#"@id("p") permit(principal,action,resource) when { principal has name && principal.name == "Alice" };"#
            ),
            r#"(User::"alice".name) == "Alice""#
        );
    }

    // --- Guarded access: has && get on optional not-in-map ---
    // `has` is a residual, so the whole expression stays as a residual.

    #[test]
    fn has_and_get_optional_not_in_map() {
        check!(
            eval_with_attrs(
                [("name", present("Alice"))],
                r#"@id("p") permit(principal,action,resource) when { principal has nickname && principal.nickname == "Ali" };"#
            ),
            r#"(User::"alice" has nickname) && ((User::"alice".nickname) == "Ali")"#
        );
    }

    // --- Contrast with Present/Unknown/Absent for required attr ---

    #[rstest]
    #[case::present(present("Alice"), "true")]
    #[case::unknown(PA::Unknown, "true")]
    #[case::absent(PA::Absent, "false")]
    fn has_required_in_map(#[case] name: PA, #[case] expected: &str) {
        check!(
            eval_with_attrs(
                [("name", name)],
                r#"@id("p") permit(principal,action,resource) when { principal has name };"#
            ),
            expected
        );
    }
}
