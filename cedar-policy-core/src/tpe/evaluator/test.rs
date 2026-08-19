use super::super::test_utils::*;
use crate::{
    ast::{Eid, EntityUID, Expr, Literal},
    parser::parse_policyset,
    tpe::{
        self,
        entities::{PartialEntities, PartialEntity},
        request::PartialRequest,
        value::{PartialAttribute as PA, PartialAttribute, PartialRecord, PartialValue},
    },
    validator::ValidatorSchema,
};
use insta::assert_snapshot;
use smol_str::SmolStr;
use std::collections::HashSet;
use std::sync::Arc;

/// Give a test module its schema, request, and entity builders.
///
/// Defines `schema()`, `setup()` (schema plus a request for the given principal/action/resource),
/// and `entity`/`empty_entity` bound to that schema — so every fixture is validated against the
/// schema it will be evaluated with.
macro_rules! test_env {
    ($src:expr, $principal:expr, $action:expr, $resource:expr) => {
        #[track_caller]
        #[allow(dead_code, reason = "not every test module names the schema directly")]
        pub(crate) fn schema() -> ValidatorSchema {
            parse_schema($src)
        }

        #[track_caller]
        #[allow(dead_code, reason = "not every test module needs the request")]
        pub(crate) fn setup() -> (ValidatorSchema, PartialRequest) {
            let schema = schema();
            let req = request_with_context(
                $principal,
                $action,
                $resource,
                Some(PartialRecord::new()),
                &schema,
            );
            (schema, req)
        }

        #[track_caller]
        #[allow(dead_code, reason = "not every test module builds a non-empty entity")]
        pub(crate) fn entity(
            ty: &str,
            id: &str,
            attrs: Option<PartialRecord>,
            tags: Option<PartialRecord>,
        ) -> PartialEntity {
            PartialEntity::new(uid(ty, id), attrs, Some(HashSet::new()), tags, &schema())
                .expect("entity should conform to the schema")
        }

        #[track_caller]
        #[allow(dead_code, reason = "not every test module builds an empty entity")]
        pub(crate) fn empty_entity(ty: &str, id: &str) -> PartialEntity {
            entity(
                ty,
                id,
                Some(PartialRecord::new()),
                Some(PartialRecord::new()),
            )
        }
    };
}

/// Build an [`EntityUID`] from a type and id.
pub(crate) fn uid(ty: &str, id: &str) -> EntityUID {
    EntityUID::from_components(ty.parse().unwrap(), Eid::new(id), None)
}

/// As [`request`], but with the given context.
#[track_caller]
pub(crate) fn request_with_context(
    principal: &str,
    action_id: &str,
    resource: &str,
    context: Option<PartialRecord>,
    schema: &ValidatorSchema,
) -> PartialRequest {
    PartialRequest::new(
        parse_partial_euid(principal),
        uid("Action", action_id),
        parse_partial_euid(resource),
        context,
        schema,
    )
    .expect("request should conform to the schema")
}

/// Partially evaluate `policy` and pretty-print the residual as Cedar text.
#[track_caller]
pub(crate) fn eval_to_cedar(
    schema: &ValidatorSchema,
    req: &PartialRequest,
    entities: impl IntoIterator<Item = PartialEntity>,
    policy: &str,
) -> String {
    let policies = parse_policyset(policy).unwrap();
    let ents = PartialEntities::from_entities(entities.into_iter(), schema).unwrap();
    let response = tpe::is_authorized(&policies, req, &ents, schema).unwrap();
    let id = policies.static_policies().next().unwrap().id().clone();
    let r = Arc::unwrap_or_clone(response.get_residual_policy(&id).unwrap().get_residual());
    Expr::from(r.clone()).to_string()
}

/// Wrap a condition in a `permit` policy with id `p`.
pub(crate) fn permit_when(cond: &str) -> String {
    format!(r#"permit(principal, action, resource) when {{ {cond} }};"#)
}

/// A known-value literal attribute (`PartialAttribute::Value`).
pub(crate) fn present(v: impl Into<Literal>) -> PartialAttribute {
    PartialAttribute::Value(PartialValue::Lit(v.into()))
}

/// A known-value entity-uid attribute (`PartialAttribute::Value`).
pub(crate) fn present_uid(ty: &str, id: &str) -> PartialAttribute {
    PartialAttribute::Value(PartialValue::Lit(Literal::EntityUID(Arc::new(uid(ty, id)))))
}

/// A known-value record attribute (`PartialAttribute::Value`).
pub(crate) fn record(
    fields: impl IntoIterator<Item = (impl Into<SmolStr>, PartialAttribute)>,
) -> PartialAttribute {
    PartialAttribute::Value(PartialValue::Record(rec(fields)))
}

/// A [`PartialRecord`] from (key, attribute) pairs.
pub(crate) fn rec(
    fields: impl IntoIterator<Item = (impl Into<SmolStr>, PartialAttribute)>,
) -> PartialRecord {
    fields.into_iter().map(|(k, v)| (k.into(), v)).collect()
}

mod partial_attr_tests {
    use super::*;

    test_env!(
        r#"
        entity User { name: String, level: Long } tags String;
        entity Document { owner: User, public: Bool };
        action Read appliesTo { principal: User, resource: Document, context: {} };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn doc(public: PA) -> PartialEntity {
        entity(
            "Document",
            "doc",
            Some(rec([
                ("owner", present_uid("User", "alice")),
                ("public", public),
            ])),
            Some(PartialRecord::new()),
        )
    }

    fn alice() -> PartialEntity {
        entity(
            "User",
            "alice",
            Some(rec([("name", present("Alice")), ("level", present(5))])),
            Some(PartialRecord::new()),
        )
    }

    fn eval(public: PA, cond: &str) -> String {
        let (schema, req) = setup();
        eval_to_cedar(&schema, &req, [doc(public), alice()], &permit_when(cond))
    }

    fn eval_no_public(cond: &str) -> String {
        let (schema, req) = setup();
        let doc = entity(
            "Document",
            "doc",
            Some(rec([("owner", present_uid("User", "alice"))])),
            Some(PartialRecord::new()),
        );
        eval_to_cedar(&schema, &req, [doc, alice()], &permit_when(cond))
    }

    fn eval_tag(role: PA, cond: &str) -> String {
        let (schema, req) = setup();
        let alice = entity(
            "User",
            "alice",
            Some(rec([("name", present("Alice")), ("level", present(5))])),
            Some(rec([("role", role)])),
        );
        eval_to_cedar(
            &schema,
            &req,
            [doc(present(true)), alice],
            &permit_when(cond),
        )
    }

    fn eval_no_tags(cond: &str) -> String {
        let (schema, req) = setup();
        eval_to_cedar(
            &schema,
            &req,
            [doc(present(true)), alice()],
            &permit_when(cond),
        )
    }

    #[test]
    fn test_get_attr() {
        let cond = "resource.public";
        assert_snapshot!(eval(present(true), cond), @"true");
        assert_snapshot!(eval(PA::Exists, cond), @r#"Document::"doc".public"#);
        assert_snapshot!(eval_no_public(cond), @r#"Document::"doc".public"#);
    }

    #[test]
    fn test_has_attr() {
        let cond = "resource has public";
        assert_snapshot!(eval(PA::Exists, cond), @"true");
        // `public` omitted from the known attrs, yet `has` is true: required, so
        // the schema guarantees existence.
        assert_snapshot!(eval_no_public(cond), @"true");
    }

    #[test]
    fn test_tag_has_and_get() {
        let cond = r#"principal.hasTag("role") && principal.getTag("role") == "admin""#;
        assert_snapshot!(eval_tag(present("admin"), cond), @"true");
        assert_snapshot!(
            eval_tag(PA::Exists, cond),
            @r#"User::"alice".getTag("role") == "admin""#
        );
        assert_snapshot!(eval_tag(PA::Absent, cond), @"false");
        assert_snapshot!(
            eval_no_tags(cond),
            @r#"User::"alice".hasTag("role") && (User::"alice".getTag("role") == "admin")"#
        );
    }
}

mod nested_partial_attr_tests {
    use super::*;

    test_env!(
        r#"
        entity User;
        entity Document { meta: { title: String, rating: Long }, public: Bool };
        action Read appliesTo { principal: User, resource: Document, context: {} };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn doc(meta: PA) -> PartialEntity {
        entity(
            "Document",
            "doc",
            Some(rec([("meta", meta), ("public", present(true))])),
            Some(PartialRecord::new()),
        )
    }

    fn eval(meta: PA, cond: &str) -> String {
        let (schema, req) = setup();
        eval_to_cedar(
            &schema,
            &req,
            [doc(meta), empty_entity("User", "alice")],
            &permit_when(cond),
        )
    }

    #[test]
    fn test_record_value_is_error_free() {
        let meta = record([("title", PA::Exists), ("rating", present(5))]);
        assert_snapshot!(
            eval(meta.clone(), r#"resource.meta == {title: "x", rating: 5} && 1 == 2"#),
            @"false"
        );
    }

    #[test]
    fn test_title_eq() {
        let cond = r#"resource.meta.title == "My Doc""#;
        assert_snapshot!(
            eval(record([("title", present("My Doc")), ("rating", present(5))]), cond),
            @"true"
        );
        assert_snapshot!(
            eval(record([("title", PA::Exists), ("rating", present(5))]), cond),
            @r#"Document::"doc".meta.title == "My Doc""#
        );
    }

    #[test]
    fn test_has_title() {
        let cond = "resource.meta has title";
        assert_snapshot!(
            eval(record([("title", PA::Exists), ("rating", present(5))]), cond),
            @"true"
        );
        assert_snapshot!(eval(record([("rating", present(5))]), cond), @"true");
        assert_snapshot!(eval(PA::Exists, cond), @r#"Document::"doc".meta has title"#);
    }

    #[test]
    fn test_mixed_known_and_unknown_fields() {
        assert_snapshot!(
            eval(
                record([("title", PA::Exists), ("rating", present(5))]),
                r#"resource.meta.rating < 10 && resource.meta.title == "My Doc""#,
            ),
            @r#"Document::"doc".meta.title == "My Doc""#
        );
    }

    #[test]
    fn test_record_equality() {
        let cond = r#"resource.meta == {title: "My Doc", rating: 5}"#;
        assert_snapshot!(
            eval(record([("title", present("My Doc")), ("rating", present(5))]), cond),
            @"true"
        );
        assert_snapshot!(
            eval(record([("title", present("Other")), ("rating", present(5))]), cond),
            @"false"
        );
        // `rating` is 6 here, not 5, but the residual re-emits `resource.meta`
        // rather than a rebuilt literal, so the compared value reads `rating: 5`.
        assert_snapshot!(
            eval(record([("title", PA::Exists), ("rating", present(6))]), cond),
            @r#"Document::"doc".meta == {rating: 5, title: "My Doc"}"#
        );
    }
}

mod partial_record_tag_tests {
    use super::*;

    test_env!(
        r#"
        entity User tags { role: String, level: Long };
        entity Document;
        action Read appliesTo { principal: User, resource: Document, context: {} };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn eval(val: PA, cond: &str) -> String {
        let (schema, req) = setup();
        let alice = entity(
            "User",
            "alice",
            Some(PartialRecord::new()),
            Some(rec([("info", val)])),
        );
        eval_to_cedar(
            &schema,
            &req,
            [alice, empty_entity("Document", "doc")],
            &permit_when(cond),
        )
    }

    #[test]
    fn test_get_role() {
        let cond = r#"principal.hasTag("info") && principal.getTag("info").role == "admin""#;
        assert_snapshot!(
            eval(record([("role", present("admin")), ("level", present(5))]), cond),
            @"true"
        );
        assert_snapshot!(
            eval(record([("role", PA::Exists), ("level", present(5))]), cond),
            @r#"User::"alice".getTag("info").role == "admin""#
        );
        assert_snapshot!(
            eval(record([("level", present(5))]), cond),
            @r#"User::"alice".getTag("info").role == "admin""#
        );
    }

    #[test]
    fn test_known_sibling_resolves() {
        assert_snapshot!(
            eval(
                record([("role", PA::Exists), ("level", present(5))]),
                r#"principal.hasTag("info") && principal.getTag("info").level < 10"#,
            ),
            @"true"
        );
    }
}

mod optional_attr_tests {
    use super::*;

    test_env!(
        r#"
        entity User { name: String, nickname?: String };
        entity Document;
        action Read appliesTo { principal: User, resource: Document, context: {} };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn eval(nickname: PA, cond: &str) -> String {
        let (schema, req) = setup();
        let alice = entity(
            "User",
            "alice",
            Some(rec([("name", present("Alice")), ("nickname", nickname)])),
            Some(PartialRecord::new()),
        );
        eval_to_cedar(
            &schema,
            &req,
            [alice, empty_entity("Document", "doc")],
            &permit_when(cond),
        )
    }

    fn eval_no_nickname(cond: &str) -> String {
        let (schema, req) = setup();
        let alice = entity(
            "User",
            "alice",
            Some(rec([("name", present("Alice"))])),
            Some(PartialRecord::new()),
        );
        eval_to_cedar(
            &schema,
            &req,
            [alice, empty_entity("Document", "doc")],
            &permit_when(cond),
        )
    }

    #[test]
    fn test_has() {
        let cond = "principal has nickname";
        assert_snapshot!(eval(present("Ali"), cond), @"true");
        assert_snapshot!(eval(PA::Exists, cond), @"true");
        assert_snapshot!(eval(PA::Absent, cond), @"false");
        assert_snapshot!(eval_no_nickname(cond), @r#"User::"alice" has nickname"#);
    }

    #[test]
    fn test_guarded() {
        let cond = r#"principal has nickname && principal.nickname == "Ali""#;
        assert_snapshot!(eval(present("Ali"), cond), @"true");
        assert_snapshot!(eval(PA::Exists, cond), @r#"User::"alice".nickname == "Ali""#);
        assert_snapshot!(eval(PA::Absent, cond), @"false");
        assert_snapshot!(
            eval_no_nickname(cond),
            @r#"(User::"alice" has nickname) && (User::"alice".nickname == "Ali")"#
        );
    }
}

mod nested_optional_attr_tests {
    use super::*;

    test_env!(
        r#"
        entity User;
        entity Document { meta: { title: String, subtitle?: String } };
        action Read appliesTo { principal: User, resource: Document, context: {} };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn eval(meta: PA, cond: &str) -> String {
        let (schema, req) = setup();
        let doc = entity(
            "Document",
            "doc",
            Some(rec([("meta", meta)])),
            Some(PartialRecord::new()),
        );
        eval_to_cedar(
            &schema,
            &req,
            [doc, empty_entity("User", "alice")],
            &permit_when(cond),
        )
    }

    #[test]
    fn test_has_subtitle() {
        let cond = "resource.meta has subtitle";
        assert_snapshot!(
            eval(record([("title", present("Doc")), ("subtitle", present("Sub"))]), cond),
            @"true"
        );
        assert_snapshot!(
            eval(record([("title", present("Doc")), ("subtitle", PA::Exists)]), cond),
            @"true"
        );
        assert_snapshot!(
            eval(record([("title", present("Doc")), ("subtitle", PA::Absent)]), cond),
            @"false"
        );
        assert_snapshot!(
            eval(record([("title", present("Doc"))]), cond),
            @r#"Document::"doc".meta has subtitle"#
        );
    }

    #[test]
    fn test_guarded_subtitle() {
        let cond = r#"resource.meta has subtitle && resource.meta.subtitle == "Sub""#;
        assert_snapshot!(
            eval(record([("title", present("Doc")), ("subtitle", present("Sub"))]), cond),
            @"true"
        );
        assert_snapshot!(
            eval(record([("title", present("Doc")), ("subtitle", PA::Exists)]), cond),
            @r#"Document::"doc".meta.subtitle == "Sub""#
        );
        assert_snapshot!(
            eval(record([("title", present("Doc")), ("subtitle", PA::Absent)]), cond),
            @"false"
        );
        assert_snapshot!(
            eval(record([("title", present("Doc"))]), cond),
            @r#"(Document::"doc".meta has subtitle) && (Document::"doc".meta.subtitle == "Sub")"#
        );
    }
}

mod context_tests {
    use super::*;

    test_env!(
        r#"
        entity User;
        entity Document;
        action Read appliesTo {
            principal: User,
            resource: Document,
            context: { level: Long, tag?: String }
        };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn eval_ctx(context: Option<PartialRecord>, cond: &str) -> String {
        let schema = schema();
        let req = request_with_context(
            r#"User::"alice""#,
            "Read",
            r#"Document::"doc""#,
            context,
            &schema,
        );
        eval_to_cedar(
            &schema,
            &req,
            [
                empty_entity("User", "alice"),
                empty_entity("Document", "doc"),
            ],
            &permit_when(cond),
        )
    }

    fn ctx(fields: impl IntoIterator<Item = (&'static str, PA)>) -> Option<PartialRecord> {
        Some(rec(fields))
    }

    #[test]
    fn test_context_level() {
        let cond = "context.level < 10";
        assert_snapshot!(eval_ctx(ctx([("level", present(5))]), cond), @"true");
        assert_snapshot!(eval_ctx(None, cond), @"context.level < 10");
        assert_snapshot!(
            eval_ctx(ctx([("level", PA::Exists)]), cond),
            @"context.level < 10"
        );
    }

    #[test]
    fn test_context_optional_tag() {
        let cond = r#"context has tag && context.tag == "admin""#;
        assert_snapshot!(
            eval_ctx(ctx([("level", present(5)), ("tag", present("admin"))]), cond),
            @"true"
        );
        assert_snapshot!(
            eval_ctx(ctx([("level", present(5)), ("tag", PA::Absent)]), cond),
            @"false"
        );
        assert_snapshot!(
            eval_ctx(ctx([("level", present(5)), ("tag", PA::Exists)]), cond),
            @r#"context.tag == "admin""#
        );
        assert_snapshot!(
            eval_ctx(ctx([("level", present(5))]), cond),
            @r#"(context has tag) && (context.tag == "admin")"#
        );
        assert_snapshot!(
            eval_ctx(None, cond),
            @r#"(context has tag) && (context.tag == "admin")"#
        );
    }
}

mod required_attr_not_in_map_tests {
    use super::*;

    test_env!(
        r#"
        entity User { name: String, nickname?: String };
        entity Document;
        action Read appliesTo { principal: User, resource: Document, context: {} };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn eval_with_attrs(attrs: impl IntoIterator<Item = (&'static str, PA)>, cond: &str) -> String {
        let (schema, req) = setup();
        let alice = entity(
            "User",
            "alice",
            Some(rec(attrs)),
            Some(PartialRecord::new()),
        );
        eval_to_cedar(
            &schema,
            &req,
            [alice, empty_entity("Document", "doc")],
            &permit_when(cond),
        )
    }

    #[test]
    fn test_required_not_in_map() {
        assert_snapshot!(eval_with_attrs([], "principal has name"), @"true");
        assert_snapshot!(
            eval_with_attrs([], r#"principal.name == "Alice""#),
            @r#"User::"alice".name == "Alice""#
        );
        assert_snapshot!(
            eval_with_attrs([], r#"principal has name && principal.name == "Alice""#),
            @r#"User::"alice".name == "Alice""#
        );
    }

    #[test]
    fn test_optional_not_in_map() {
        let name = [("name", present("Alice"))];
        assert_snapshot!(
            eval_with_attrs(name.clone(), "principal has nickname"),
            @r#"User::"alice" has nickname"#
        );
        assert_snapshot!(
            eval_with_attrs(
                name,
                r#"principal has nickname && principal.nickname == "Ali""#,
            ),
            @r#"(User::"alice" has nickname) && (User::"alice".nickname == "Ali")"#
        );
    }

    #[test]
    fn test_required_in_map() {
        let cond = "principal has name";
        assert_snapshot!(eval_with_attrs([("name", present("Alice"))], cond), @"true");
        assert_snapshot!(eval_with_attrs([("name", PA::Exists)], cond), @"true");
    }
}

/// Unknown attrs/tags (`None`) differ from a known-but-partial map: even a
/// required attr's access stays residual (contrast `required_not_in_map`).
mod unknown_entity_data_tests {
    use super::*;

    test_env!(
        r#"
        entity User { name: String } tags String;
        entity Document;
        action Read appliesTo { principal: User, resource: Document, context: {} };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn eval(cond: &str) -> String {
        let (schema, req) = setup();
        let alice = entity("User", "alice", None, None);
        eval_to_cedar(
            &schema,
            &req,
            [alice, empty_entity("Document", "doc")],
            &permit_when(cond),
        )
    }

    #[test]
    fn test_attrs() {
        assert_snapshot!(eval("principal has name"), @r#"User::"alice" has name"#);
        assert_snapshot!(
            eval(r#"principal.name == "Alice""#),
            @r#"User::"alice".name == "Alice""#
        );
        assert_snapshot!(
            eval(r#"principal has name && principal.name == "Alice""#),
            @r#"(User::"alice" has name) && (User::"alice".name == "Alice")"#
        );
    }

    #[test]
    fn test_tags() {
        assert_snapshot!(eval(r#"principal.hasTag("t")"#), @r#"User::"alice".hasTag("t")"#);
        assert_snapshot!(
            eval(r#"principal.hasTag("t") && principal.getTag("t") == "x""#),
            @r#"User::"alice".hasTag("t") && (User::"alice".getTag("t") == "x")"#
        );
    }
}

/// Record *literals*: Cedar evaluates every field, so an erroring sibling
/// poisons the whole record and field extraction must not bypass it.
mod record_literal_tests {
    use super::*;

    test_env!(
        r#"
        entity User { level: Long };
        entity Document;
        action Read appliesTo { principal: User, resource: Document, context: {} };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn eval(level: PA, cond: &str) -> String {
        let (schema, req) = setup();
        let alice = entity(
            "User",
            "alice",
            Some(rec([("level", level)])),
            Some(PartialRecord::new()),
        );
        eval_to_cedar(
            &schema,
            &req,
            [alice, empty_entity("Document", "doc")],
            &permit_when(cond),
        )
    }

    #[test]
    fn test_all_concrete() {
        assert_snapshot!(eval(present(5), "{a: 1, b: 2}.a == 1"), @"true");
        assert_snapshot!(eval(present(5), "{a: 1, b: 2} has a"), @"true");
        assert_snapshot!(eval(present(5), "{a: 1, b: 2} has c"), @"false");
        assert_snapshot!(eval(present(5), "{a: 1} == {a: 1}"), @"true");
        assert_snapshot!(eval(present(5), "{a: 1} == {a: 2}"), @"false");
        assert_snapshot!(
            eval(present(5), "{a: {b: {c: 3}}}.a.b.c == 3"),
            @"true"
        );
    }

    #[test]
    fn test_sibling_error_poisons_literal() {
        // Overflow in `e` errors the record, so reading `l` errors too.
        let overflow = "{e: 9223372036854775807 + 1, l: 0}";
        assert_snapshot!(eval(present(5), &format!("{overflow}.l == 0")), @"error()");
        assert_snapshot!(eval(present(5), &format!("{overflow} has l")), @"error()");
        assert_snapshot!(
            eval(present(5), "{outer: {e: 9223372036854775807 + 1, l: 0}}.outer.l == 0"),
            @"error()"
        );
    }

    // The residual field may error once known, so a concrete sibling can't
    // be extracted.
    #[test]
    fn test_residual_sibling_blocks_extraction() {
        assert_snapshot!(
            eval(PA::Exists, "{e: principal.level + 1, l: 0}.l == 0"),
            @r#"{e: User::"alice".level + 1, l: 0}.l == 0"#
        );
        assert_snapshot!(
            eval(PA::Exists, "{e: principal.level + 1, l: 0} has l"),
            @r#"{e: User::"alice".level + 1, l: 0} has l"#
        );
        // `has` is likewise unanswered: if the sibling errors, so does `has`.
        assert_snapshot!(
            eval(PA::Exists, "{e: principal.level + 1, l: 0} has missing"),
            @r#"{e: User::"alice".level + 1, l: 0} has missing"#
        );
        assert_snapshot!(
            eval(PA::Exists, "{e: principal.level + 1, l: 0}.e < 10"),
            @r#"{e: User::"alice".level + 1, l: 0}.e < 10"#
        );
    }

    #[test]
    fn test_error_branch_eliminated_by_known_guard() {
        assert_snapshot!(
            eval(
                present(5),
                "{e: if principal.level < 10 then 1 else 9223372036854775807 + 1, l: 0}.l == 0"
            ),
            @"true"
        );
        assert_snapshot!(
            eval(
                PA::Exists,
                "{e: if principal.level < 10 then 1 else 9223372036854775807 + 1, l: 0}.l == 0"
            ),
            @r#"{e: if User::"alice".level < 10 then 1 else error(), l: 0}.l == 0"#
        );
    }

    #[test]
    fn test_nested_literal_error_propagates_outward() {
        assert_snapshot!(
            eval(present(5), "{outer: {e: 9223372036854775807 + 1}, l: 0}.l == 0"),
            @"error()"
        );
    }

    // `principal` provably cannot error, yet still blocks extraction under the
    // current conservative rule. A precision gap, not unsoundness; pinned so an
    // improvement shows up as a snapshot change.
    #[test]
    fn test_non_erroring_residual_sibling_still_blocks() {
        // An unknown principal, so its own schema and request rather than the module's.
        mod unknown_principal {
            use super::super::*;
            test_env!(
                r#"
                entity User;
                entity Document;
                action Read appliesTo { principal: User, resource: Document, context: {} };
                "#,
                "User",
                "Read",
                r#"Document::"doc""#
            );
        }
        let (schema, req) = unknown_principal::setup();
        let out = eval_to_cedar(
            &schema,
            &req,
            [unknown_principal::empty_entity("Document", "doc")],
            &permit_when("{p: principal, l: 0}.l == 0"),
        );
        assert_snapshot!(out, @"{l: 0, p: principal}.l == 0");
    }

    // Contrast: the same shape from entity *data* does allow extraction.
    #[test]
    fn test_record_value_contrast_extraction_allowed() {
        // A record-valued attribute, so its own schema rather than the module's.
        mod record_attr {
            use super::super::*;
            test_env!(
                r#"
                entity User { meta: { e: Long, l: Long } };
                entity Document;
                action Read appliesTo { principal: User, resource: Document, context: {} };
                "#,
                r#"User::"alice""#,
                "Read",
                r#"Document::"doc""#
            );
        }
        use record_attr::{empty_entity, entity};
        let (schema, req) = record_attr::setup();
        let alice = entity(
            "User",
            "alice",
            Some(rec([(
                "meta",
                record([("e", PA::Exists), ("l", present(0))]),
            )])),
            Some(PartialRecord::new()),
        );
        let out = eval_to_cedar(
            &schema,
            &req,
            [alice, empty_entity("Document", "doc")],
            &permit_when("principal.meta.l == 0"),
        );
        assert_snapshot!(out, @"true");
    }
}

/// Interpreting a residual again with more entity data, as `is_authorized_batched` does.
mod iterated_eval_tests {
    use super::*;
    use crate::extensions::Extensions;
    use crate::parser::parse_policyset;
    use crate::tpe::entities::PartialEntities;
    use crate::tpe::residual::Residual;
    use crate::tpe::Evaluator;

    test_env!(
        r#"
        entity Other { data: Long };
        entity User { meta: { other: Other, level: Long } };
        entity Document;
        action Read appliesTo { principal: User, resource: Document, context: {} };
        "#,
        r#"User::"alice""#,
        "Read",
        r#"Document::"doc""#
    );

    fn alice() -> PartialEntity {
        entity(
            "User",
            "alice",
            Some(rec([(
                "meta",
                record([("other", present_uid("Other", "o")), ("level", present(1))]),
            )])),
            Some(PartialRecord::new()),
        )
    }

    /// As [`alice`], but `meta.level` is only known to exist, so `meta` cannot
    /// fold to a concrete record.
    fn alice_partial_meta() -> PartialEntity {
        entity(
            "User",
            "alice",
            Some(rec([(
                "meta",
                record([("other", present_uid("Other", "o")), ("level", PA::Exists)]),
            )])),
            Some(PartialRecord::new()),
        )
    }

    fn other() -> PartialEntity {
        entity(
            "Other",
            "o",
            Some(rec([("data", present(42))])),
            Some(PartialRecord::new()),
        )
    }

    /// Interpret `cond` against `round1` entities, then interpret the resulting
    /// residual again against `round2`.
    #[track_caller]
    fn eval_twice(
        round1: impl IntoIterator<Item = PartialEntity>,
        round2: impl IntoIterator<Item = PartialEntity>,
        cond: &str,
    ) -> (String, String) {
        let schema = schema();
        let req = request_with_context(
            r#"User::"alice""#,
            "Read",
            r#"Document::"doc""#,
            Some(PartialRecord::new()),
            &schema,
        );
        let policies = parse_policyset(&permit_when(cond)).unwrap();

        let render = |r: &Residual| Expr::from(r.clone()).to_string();

        let ents1 = PartialEntities::from_entities(round1.into_iter(), &schema).unwrap();
        let residuals = tpe::policy_residual_map(&req, &policies, &schema).unwrap();
        let expr = residuals.into_values().next().unwrap();
        let first = Evaluator {
            request: &req,
            entities: &ents1,
            schema: &schema,
            extensions: Extensions::all_available(),
        }
        .interpret(&expr);

        let ents2 = PartialEntities::from_entities(round2.into_iter(), &schema).unwrap();
        let second = Evaluator {
            request: &req,
            entities: &ents2,
            schema: &schema,
            extensions: Extensions::all_available(),
        }
        .interpret(&first);

        (render(&first), render(&second))
    }

    #[test]
    fn test_access_through_record_value_reduces_on_later_round() {
        let (first, second) = eval_twice(
            [alice(), empty_entity("Document", "doc")],
            [alice(), other(), empty_entity("Document", "doc")],
            "principal.meta.other.data == 42",
        );
        assert_snapshot!(first, @r#"Other::"o".data == 42"#);
        assert_snapshot!(second, @"true");
    }

    #[test]
    fn test_record_value_base_arriving_late() {
        let (first, second) = eval_twice(
            [empty_entity("Document", "doc")],
            [alice(), empty_entity("Document", "doc")],
            r#"principal.meta == {other: Other::"o", level: 1}"#,
        );
        assert_snapshot!(first, @r#"User::"alice".meta == {level: 1, other: Other::"o"}"#);
        assert_snapshot!(second, @"true");
    }

    #[test]
    fn test_record_value_snapshot_is_refreshed_with_fuller_data() {
        // Round 1 knows only that `meta.level` exists; round 2 knows its value.
        let (first, second) = eval_twice(
            [alice_partial_meta(), empty_entity("Document", "doc")],
            [alice(), other(), empty_entity("Document", "doc")],
            r#"principal.meta == {other: Other::"o", level: 1}"#,
        );
        assert_snapshot!(first, @r#"User::"alice".meta == {level: 1, other: Other::"o"}"#);
        assert_snapshot!(second, @"true");
    }
}
