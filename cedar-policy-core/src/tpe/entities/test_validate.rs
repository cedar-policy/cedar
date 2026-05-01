use std::collections::HashSet;

use crate::entities::conformance::err::EntitySchemaConformanceError;
use crate::extensions::Extensions;
use crate::tpe::entities::PartialEntity;
use crate::tpe::err::{
    EntityValidationError, MismatchedActionAncestorsError, UnknownActionComponentError,
};
use crate::tpe::value::{PartialAttribute, PartialRecord, PartialValue};
use crate::validator::ValidatorSchema;
use cool_asserts::assert_matches;

fn test_schema() -> ValidatorSchema {
    ValidatorSchema::from_cedarschema_str(
        r#"
        entity User {
            name: String,
        } tags String;

        entity Resource;

        action view appliesTo {
            principal: User,
            resource: Resource
        };
        "#,
        Extensions::all_available(),
    )
    .unwrap()
    .0
}

/// Helper: build a PartialRecord from (key, Value) pairs
fn record_from_lits(
    pairs: impl IntoIterator<Item = (smol_str::SmolStr, crate::ast::Literal)>,
) -> PartialRecord {
    PartialRecord::from_attrs(
        pairs
            .into_iter()
            .map(|(k, v)| (k, PartialAttribute::Present(PartialValue::Lit(v)))),
    )
}

#[test]
fn valid_entity() {
    let schema = test_schema();
    let entity = PartialEntity {
        uid: "User::\"alice\"".parse().unwrap(),
        attrs: Some(record_from_lits([("name".into(), "Alice".into())])),
        ancestors: Some(HashSet::new()),
        tags: Some(record_from_lits([(
            "department".into(),
            "Engineering".into(),
        )])),
    };

    assert_matches!(entity.validate(&schema), Ok(()));
}

#[test]
fn valid_entity_with_unknown_attrs() {
    let schema = test_schema();
    let entity = PartialEntity {
        uid: "User::\"alice\"".parse().unwrap(),
        attrs: None,
        ancestors: Some(HashSet::new()),
        tags: None,
    };

    assert_matches!(entity.validate(&schema), Ok(()));
}

#[test]
fn valid_entity_with_unknown_individual_attr() {
    let schema = test_schema();
    // "name" is required but Unknown — we can't prove it's missing, so pass
    let attrs = PartialRecord::from_attrs([("name".into(), PartialAttribute::Unknown)]);
    let entity = PartialEntity {
        uid: "User::\"alice\"".parse().unwrap(),
        attrs: Some(attrs),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(entity.validate(&schema), Ok(()));
}

#[test]
fn valid_entity_with_nested_unknown_in_record_attr() {
    // Schema with a record-typed attribute containing nested fields
    let schema = ValidatorSchema::from_cedarschema_str(
        r#"
        entity Item {
            info: { name: String, count: Long },
        };
        "#,
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    // "info" is present as a record, but "count" inside it is unknown.
    // "name" inside it is present and correct — it should be validated.
    let inner_record = PartialRecord::from_attrs([
        (
            "name".into(),
            PartialAttribute::Present(PartialValue::Lit("hello".into())),
        ),
        ("count".into(), PartialAttribute::Unknown),
    ]);
    let entity = PartialEntity {
        uid: "Item::\"i1\"".parse().unwrap(),
        attrs: Some(PartialRecord::from_attrs([(
            "info".into(),
            PartialAttribute::Present(PartialValue::Record(inner_record)),
        )])),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(entity.validate(&schema), Ok(()));
}

#[test]
fn invalid_entity_with_nested_wrong_type_in_partial_record() {
    let schema = ValidatorSchema::from_cedarschema_str(
        r#"
        entity Item {
            info: { name: String, count: Long },
        };
        "#,
        Extensions::all_available(),
    )
    .unwrap()
    .0;

    // "name" is present but wrong type (Long instead of String) — should fail
    // "count" is unknown — should be skipped
    let inner_record = PartialRecord::from_attrs([
        (
            "name".into(),
            PartialAttribute::Present(PartialValue::Lit(42.into())),
        ),
        ("count".into(), PartialAttribute::Unknown),
    ]);
    let entity = PartialEntity {
        uid: "Item::\"i1\"".parse().unwrap(),
        attrs: Some(PartialRecord::from_attrs([(
            "info".into(),
            PartialAttribute::Present(PartialValue::Record(inner_record)),
        )])),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(
        entity.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::TypeMismatch(_)
        ))
    );
}

#[test]
fn valid_action() {
    let schema = test_schema();
    let action = PartialEntity {
        uid: "Action::\"view\"".parse().unwrap(),
        attrs: Some(PartialRecord::new()),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(action.validate(&schema), Ok(()));
}

#[test]
fn invalid_action_with_unknown_ancestors() {
    let schema = test_schema();
    let action = PartialEntity {
        uid: "Action::\"view\"".parse().unwrap(),
        attrs: Some(PartialRecord::new()),
        ancestors: None,
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(
        action.validate(&schema),
        Err(EntityValidationError::UnknownActionComponent(
            UnknownActionComponentError { .. }
        ))
    );
}

#[test]
fn invalid_action_with_unknown_tags() {
    let schema = test_schema();
    let action = PartialEntity {
        uid: "Action::\"view\"".parse().unwrap(),
        attrs: Some(PartialRecord::new()),
        ancestors: Some(HashSet::new()),
        tags: None,
    };

    assert_matches!(
        action.validate(&schema),
        Err(EntityValidationError::UnknownActionComponent(
            UnknownActionComponentError { .. }
        ))
    );
}

#[test]
fn invalid_action_with_unknown_attrs() {
    let schema = test_schema();
    let action = PartialEntity {
        uid: "Action::\"view\"".parse().unwrap(),
        attrs: None,
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(
        action.validate(&schema),
        Err(EntityValidationError::UnknownActionComponent(
            UnknownActionComponentError { .. }
        ))
    );
}

#[test]
fn invalid_action_with_unexpected_attr() {
    let schema = test_schema();
    let action = PartialEntity {
        uid: "Action::\"view\"".parse().unwrap(),
        attrs: Some(record_from_lits([(
            "unexpected_attr".into(),
            "value".into(),
        )])),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(
        action.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::UnexpectedEntityAttr(_)
        ))
    );
}

#[test]
fn invalid_action_with_unexpected_tag() {
    let schema = test_schema();
    let action = PartialEntity {
        uid: "Action::\"view\"".parse().unwrap(),
        attrs: Some(PartialRecord::new()),
        ancestors: Some(HashSet::new()),
        tags: Some(record_from_lits([(
            "unexpected_tag".into(),
            "value".into(),
        )])),
    };

    assert_matches!(
        action.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::UnexpectedEntityTag(_)
        ))
    );
}

#[test]
fn invalid_action_with_incorrect_ancestors() {
    let schema = test_schema();
    let action = PartialEntity {
        uid: "Action::\"view\"".parse().unwrap(),
        attrs: Some(PartialRecord::new()),
        ancestors: Some(HashSet::from_iter(["Action::\"other\"".parse().unwrap()])),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(
        action.validate(&schema),
        Err(EntityValidationError::MismatchedActionAncestors(
            MismatchedActionAncestorsError { .. }
        ))
    );
}

#[test]
fn invalid_unexpected_action() {
    let schema = test_schema();
    let action = PartialEntity {
        uid: "Action::\"other\"".parse().unwrap(),
        attrs: Some(PartialRecord::new()),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(
        action.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::UndeclaredAction(_)
        ))
    );
}

#[test]
fn invalid_unexpected_entity_type() {
    let schema = test_schema();
    let entity = PartialEntity {
        uid: "UnknownType::\"test\"".parse().unwrap(),
        attrs: None,
        ancestors: None,
        tags: None,
    };

    assert_matches!(
        entity.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::UnexpectedEntityType(_)
        ))
    );
}

#[test]
fn invalid_entity_invalid_ancestor() {
    let schema = test_schema();
    let entity = PartialEntity {
        uid: "User::\"alice\"".parse().unwrap(),
        attrs: None,
        ancestors: Some(HashSet::from_iter(["Resource::\"doc1\"".parse().unwrap()])),
        tags: None,
    };

    assert_matches!(
        entity.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::InvalidAncestorType(_)
        ))
    );
}

#[test]
fn invalid_entity_invalid_attr() {
    let schema = test_schema();
    let entity = PartialEntity {
        uid: "User::\"alice\"".parse().unwrap(),
        attrs: Some(record_from_lits([("name".into(), 42.into())])),
        ancestors: None,
        tags: None,
    };

    assert_matches!(
        entity.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::TypeMismatch(_)
        ))
    );
}

#[test]
fn invalid_entity_invalid_tag() {
    let schema = test_schema();
    let entity = PartialEntity {
        uid: "User::\"alice\"".parse().unwrap(),
        attrs: None,
        ancestors: None,
        tags: Some(record_from_lits([("department".into(), 42.into())])),
    };

    assert_matches!(
        entity.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::TypeMismatch(_)
        ))
    );
}

#[test]
fn invalid_entity_unexpected_unknown_attr() {
    let schema = test_schema();
    // "bogus" is not in the User schema — even with Unknown value, it's rejected
    let entity = PartialEntity {
        uid: "User::\"alice\"".parse().unwrap(),
        attrs: Some(PartialRecord::from_attrs([
            (
                "name".into(),
                PartialAttribute::Present(PartialValue::Lit("Alice".into())),
            ),
            ("bogus".into(), PartialAttribute::Unknown),
        ])),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(
        entity.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::UnexpectedEntityAttr(_)
        ))
    );
}

#[test]
fn invalid_entity_unexpected_unknown_tag() {
    // Resource has no tags in the schema
    let schema = test_schema();
    let entity = PartialEntity {
        uid: "Resource::\"r1\"".parse().unwrap(),
        attrs: Some(PartialRecord::new()),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::from_attrs([(
            "sometag".into(),
            PartialAttribute::Unknown,
        )])),
    };

    assert_matches!(
        entity.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::UnexpectedEntityTag(_)
        ))
    );
}

#[test]
fn invalid_entity_absent_required_attr() {
    let schema = test_schema();
    // "name" is required and explicitly Absent — definitive error
    let entity = PartialEntity {
        uid: "User::\"alice\"".parse().unwrap(),
        attrs: Some(PartialRecord::from_attrs([(
            "name".into(),
            PartialAttribute::Absent,
        )])),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(
        entity.validate(&schema),
        Err(EntityValidationError::Concrete(
            EntitySchemaConformanceError::MissingRequiredEntityAttr(_)
        ))
    );
}

#[test]
fn valid_entity_absent_unexpected_attr() {
    let schema = test_schema();
    // "bogus" is Absent — it doesn't exist, so no error
    let entity = PartialEntity {
        uid: "User::\"alice\"".parse().unwrap(),
        attrs: Some(PartialRecord::from_attrs([
            (
                "name".into(),
                PartialAttribute::Present(PartialValue::Lit("Alice".into())),
            ),
            ("bogus".into(), PartialAttribute::Absent),
        ])),
        ancestors: Some(HashSet::new()),
        tags: Some(PartialRecord::new()),
    };

    assert_matches!(entity.validate(&schema), Ok(()));
}
