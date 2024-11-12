//! Entity Slicing

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;

use cedar_policy_core::entities::err::EntitiesError;
use cedar_policy_core::entities::Dereference;
use cedar_policy_core::{
    ast::{Entity, EntityUID, Literal, PartialValue, Request, Value, ValueKind},
    entities::Entities,
};
use miette::Diagnostic;
use smol_str::SmolStr;
use thiserror::Error;

use crate::entity_manifest::loader::{
    load_entities, AncestorsRequest, EntityAnswer, EntityLoader, EntityRequest,
};
use crate::entity_manifest::{AccessTrie, EntityManifest, PartialRequestError};

/// Error when expressions are partial during entity
/// slicing.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error(
    "Entity slicing requires fully concrete policies. Got a policy with an unknown expression."
)]
pub struct PartialExpressionError {}

impl Diagnostic for PartialExpressionError {}

/// Error when expressions are partial during entity
/// slicing.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error(
    "Entity slicing requires fully concrete policies. Got a policy with an unknown expression."
)]
pub struct IncompatibleEntityManifestError {
    non_record_entity_value: Value,
}

impl Diagnostic for IncompatibleEntityManifestError {
    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(format!(
            "Expected entity or record during entity loading. Got value: {}",
            self.non_record_entity_value
        )))
    }
}

/// Error when entities are partial during entity manifest computation.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("Entity slicing requires fully concrete entities. Got a partial entity.")]
pub struct PartialEntityError {}

impl Diagnostic for PartialEntityError {}

/// Error when an entity loader returns the wrong number of entities.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity loader returned the wrong number of entities. Expected {expected} but got {got} entities")]
pub struct WrongNumberOfEntitiesError {
    pub(crate) expected: usize,
    pub(crate) got: usize,
}

/// Error when an entity loader returns a value missing an attribute.
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity loader produced entity with value {value}. Expected value to be a record with attribute {attribute}")]
pub struct NonRecordValueError {
    pub(crate) value: Value,
    pub(crate) attribute: SmolStr,
}

/// Context was partial during entity loading
// CAUTION: this type is publicly exported in `cedar-policy`.
// Don't make fields `pub`, don't make breaking changes, and use caution
// when adding public methods.
#[derive(Debug, Clone, Error, Eq, PartialEq)]
#[error("entity loader produced a partial context. Expected a concrete value")]
pub struct PartialContextError {}

/// An error generated by entity slicing.
/// TODO make public API wrapper
#[derive(Debug, Error, Diagnostic)]
pub enum EntitySliceError {
    /// An entities error was encountered
    #[error(transparent)]
    #[diagnostic(transparent)]
    Entities(#[from] EntitiesError),

    /// The request was partial
    #[error(transparent)]
    PartialRequest(#[from] PartialRequestError),
    /// A policy was partial
    #[error(transparent)]
    PartialExpression(#[from] PartialExpressionError),

    /// During entity loading, attempted to load from
    /// a type without fields.
    #[error(transparent)]
    IncompatibleEntityManifest(#[from] IncompatibleEntityManifestError),

    /// Found a partial entity during entity loading.
    #[error(transparent)]
    PartialEntity(#[from] PartialEntityError),

    /// The entity loader returned a partial context.
    #[error(transparent)]
    PartialContext(#[from] PartialContextError),

    /// The entity loader produced the wrong number of entities.
    #[error(transparent)]
    WrongNumberOfEntities(#[from] WrongNumberOfEntitiesError),
}

impl EntityManifest {
    /// Use this entity manifest to
    /// find an entity slice using an existing [`Entities`] store.
    pub fn slice_entities(
        &self,
        entities: &Entities,
        request: &Request,
    ) -> Result<Entities, EntitySliceError> {
        let mut slicer = EntitySlicer { entities };
        load_entities(self, request, &mut slicer)
    }
}

struct EntitySlicer<'a> {
    entities: &'a Entities,
}

impl<'a> EntityLoader for EntitySlicer<'a> {
    fn load_entities(
        &mut self,
        to_load: &[EntityRequest],
    ) -> Result<Vec<EntityAnswer>, EntitySliceError> {
        let mut res = vec![];
        for request in to_load {
            if let Dereference::Data(entity) = self.entities.entity(&request.entity_id) {
                // filter down the entity fields to those requested
                res.push(Some(request.access_trie.slice_entity(entity)?));
            } else {
                res.push(None);
            }
        }

        Ok(res)
    }

    fn load_ancestors(
        &mut self,
        entities: &[AncestorsRequest],
    ) -> Result<Vec<HashSet<EntityUID>>, EntitySliceError> {
        let mut res = vec![];

        for request in entities {
            if let Dereference::Data(entity) = self.entities.entity(&request.entity_id) {
                let mut ancestors = HashSet::new();

                for required_ancestor in &request.ancestors {
                    if entity.is_descendant_of(required_ancestor) {
                        ancestors.insert(required_ancestor.clone());
                    }
                }

                res.push(ancestors);
            } else {
                // if the entity isn't there, we don't need any ancestors
                res.push(HashSet::new());
            }
        }

        Ok(res)
    }
}

impl AccessTrie {
    /// Given an entities store, an entity id, and a resulting store
    /// Slice the entities and put them in the resulting store.
    fn slice_entity(&self, entity: &Entity) -> Result<Entity, EntitySliceError> {
        let mut new_entity = HashMap::<SmolStr, PartialValue>::new();
        for (field, slice) in &self.children {
            // only slice when field is available
            if let Some(pval) = entity.get(field).cloned() {
                let PartialValue::Value(val) = pval else {
                    return Err(PartialEntityError {}.into());
                };
                let sliced = slice.slice_val(&val)?;

                new_entity.insert(field.clone(), PartialValue::Value(sliced));
            }
        }

        Ok(Entity::new_with_attr_partial_value(
            entity.uid().clone(),
            new_entity,
            Default::default(),
        ))
    }

    fn slice_val(&self, val: &Value) -> Result<Value, EntitySliceError> {
        Ok(match val.value_kind() {
            ValueKind::Lit(Literal::EntityUID(_)) => {
                // entities shouldn't need to be dereferenced
                assert!(self.children.is_empty());
                val.clone()
            }
            ValueKind::Set(_) | ValueKind::ExtensionValue(_) | ValueKind::Lit(_) => {
                if !self.children.is_empty() {
                    return Err(IncompatibleEntityManifestError {
                        non_record_entity_value: val.clone(),
                    }
                    .into());
                }

                val.clone()
            }
            ValueKind::Record(record) => {
                let mut new_map = BTreeMap::<SmolStr, Value>::new();
                for (field, slice) in &self.children {
                    // only slice when field is available
                    if let Some(v) = record.get(field) {
                        new_map.insert(field.clone(), slice.slice_val(v)?);
                    }
                }

                Value::new(ValueKind::record(new_map), None)
            }
        })
    }
}

#[cfg(test)]
mod entity_slice_tests {
    use std::collections::BTreeSet;

    use cedar_policy_core::{
        ast::{Context, PolicyID, PolicySet},
        entities::{EntityJsonParser, TCComputation},
        extensions::Extensions,
        parser::parse_policy,
    };

    use crate::{entity_manifest::compute_entity_manifest, CoreSchema, ValidatorSchema};

    use super::*;

    /// The implementation of [`Eq`] and [`PartialEq`] for
    /// entities just compares entity ids.
    /// This implementation does a more traditional, deep equality
    /// check comparing attributes, ancestors, and the id.
    fn entity_deep_equal(this: &Entity, other: &Entity) -> bool {
        this.uid() == other.uid()
            && BTreeMap::from_iter(this.attrs()) == BTreeMap::from_iter(other.attrs())
            && BTreeSet::from_iter(this.ancestors()) == BTreeSet::from_iter(other.ancestors())
    }

    /// The implementation of [`Eq`] and [`PartialEq`] on [`Entities`]
    /// only checks equality by id for entities in the store.
    /// This method checks that the entities are equal deeply,
    /// using `[Entity::deep_equal]` to check equality.
    /// Note that it ignores mode
    fn entities_deep_equal(this: &Entities, other: &Entities) -> bool {
        for this_entity in this.iter() {
            let key = this_entity.uid();
            if let Dereference::Data(other_value) = other.entity(key) {
                if !entity_deep_equal(this_entity, other_value) {
                    return false;
                }
            } else {
                return false;
            }
        }

        for key in other.iter() {
            if !matches!(this.entity(key.uid()), Dereference::Data(_)) {
                return false;
            }
        }

        true
    }

    // Schema for testing in this module
    fn schema() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
};

entity Document;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
    ",
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn schema_with_hierarchy() -> ValidatorSchema {
        ValidatorSchema::from_cedarschema_str(
            "
entity User in [Document] = {
  name: String,
  manager: User,
  personaldoc: Document,
};

entity Document;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0
    }

    fn expect_entity_slice_to(
        original: serde_json::Value,
        expected: serde_json::Value,
        schema: &ValidatorSchema,
        manifest: &EntityManifest,
    ) {
        let request = Request::new(
            (
                EntityUID::with_eid_and_type("User", "oliver").unwrap(),
                None,
            ),
            (
                EntityUID::with_eid_and_type("Action", "Read").unwrap(),
                None,
            ),
            (
                EntityUID::with_eid_and_type("Document", "dummy").unwrap(),
                None,
            ),
            Context::empty(),
            Some(schema),
            Extensions::all_available(),
        )
        .unwrap();

        let schema = CoreSchema::new(schema);
        let parser: EntityJsonParser<'_, '_, CoreSchema<'_>> = EntityJsonParser::new(
            Some(&schema),
            Extensions::all_available(),
            TCComputation::AssumeAlreadyComputed,
        );
        let original_entities = parser.from_json_value(original).unwrap();

        // Entity slicing results in invalid entity stores
        // since attributes may be missing.
        let parser_without_validation: EntityJsonParser<'_, '_> = EntityJsonParser::new(
            None,
            Extensions::all_available(),
            TCComputation::AssumeAlreadyComputed,
        );
        let expected_entities = parser_without_validation.from_json_value(expected).unwrap();

        let sliced_entities = manifest
            .slice_entities(&original_entities, &request)
            .unwrap();

        // PANIC SAFETY: panic in testing when test fails
        #[allow(clippy::panic)]
        if !entities_deep_equal(&sliced_entities, &expected_entities) {
            panic!(
                "Sliced entities differed from expected. Expected:\n{}\nGot:\n{}",
                expected_entities.to_json_value().unwrap(),
                sliced_entities.to_json_value().unwrap()
            );
        }
    }

    #[test]
    fn test_simple_entity_manifest() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            "permit(principal, action, resource)
when {
    principal.name == \"John\"
};",
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = schema();

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");

        let entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "name" : "Oliver"
                    },
                    "parents" : []
                },
                {
                    "uid" : { "type" : "User", "id" : "oliver2"},
                    "attrs" : {
                        "name" : "Oliver2"
                    },
                    "parents" : []
                },
            ]
        );

        let expected_entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "name" : "Oliver"
                    },
                    "parents" : []
                },
            ]
        );

        expect_entity_slice_to(
            entities_json,
            expected_entities_json,
            &schema,
            &entity_manifest,
        );
    }

    #[test]
    #[should_panic(expected = "Sliced entities differed")]
    fn sanity_test_empty_entity_manifest() {
        let mut pset = PolicySet::new();
        let policy =
            parse_policy(None, "permit(principal, action, resource);").expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = schema();

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");

        let entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "name" : "Oliver"
                    },
                    "parents" : []
                },
                {
                    "uid" : { "type" : "User", "id" : "oliver2"},
                    "attrs" : {
                        "name" : "Oliver2"
                    },
                    "parents" : []
                },
            ]
        );

        let expected_entities_json = serde_json::json!([
            {
                "uid" : { "type" : "User", "id" : "oliver"},
                "attrs" : {
                    "name" : "Oliver"
                },
                "parents" : []
            },
            {
                "uid" : { "type" : "User", "id" : "oliver2"},
                "attrs" : {
                    "name" : "Oliver2"
                },
                "parents" : []
            },
        ]);

        expect_entity_slice_to(
            entities_json,
            expected_entities_json,
            &schema,
            &entity_manifest,
        );
    }

    #[test]
    fn test_empty_entity_manifest() {
        let mut pset = PolicySet::new();
        let policy =
            parse_policy(None, "permit(principal, action, resource);").expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = schema();

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");

        let entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "name" : "Oliver"
                    },
                    "parents" : []
                },
                {
                    "uid" : { "type" : "User", "id" : "oliver2"},
                    "attrs" : {
                        "name" : "Oliver2"
                    },
                    "parents" : []
                },
            ]
        );

        let expected_entities_json = serde_json::json!([]);

        expect_entity_slice_to(
            entities_json,
            expected_entities_json,
            &schema,
            &entity_manifest,
        );
    }

    #[test]
    fn test_entity_manifest_ancestors_skipped() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            "permit(principal, action, resource)
when {
    principal in resource || principal.manager in resource
};",
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = schema_with_hierarchy();

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");

        let entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "name" : "Oliver",
                        "manager": { "type" : "User", "id" : "george"},
                        "personaldoc": { "type" : "Document", "id" : "oliverdocument"}
                    },
                    "parents" : [
                        { "type" : "Document", "id" : "oliverdocument"},
                        { "type" : "Document", "id" : "dummy"}
                    ]
                },
                {
                    "uid" : { "type" : "User", "id" : "george"},
                    "attrs" : {
                        "name" : "George",
                        "manager": { "type" : "User", "id" : "george"},
                        "personaldoc": { "type" : "Document", "id" : "georgedocument"}
                    },
                    "parents" : [
                    ]
                },
            ]
        );

        let expected_entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "manager": { "__entity": { "type" : "User", "id" : "george"} }
                    },
                    "parents" : [
                        { "type" : "Document", "id" : "dummy"}
                    ]
                },
                {
                    "uid" : { "type" : "User", "id" : "george"},
                    "attrs" : {
                    },
                    "parents" : [
                    ]
                },
            ]
        );

        expect_entity_slice_to(
            entities_json,
            expected_entities_json,
            &schema,
            &entity_manifest,
        );
    }

    #[test]
    fn test_entity_manifest_possible_ancestors() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            "permit(principal, action, resource)
when {
    principal in (if 2 > 3
                  then Document::\"dummy\"
                  else principal.personaldoc)
};",
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = schema_with_hierarchy();

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");

        let entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "name" : "Oliver",
                        "manager": { "type" : "User", "id" : "george"},
                        "personaldoc": { "type" : "Document", "id" : "oliverdocument"}
                    },
                    "parents" : [
                        { "type" : "Document", "id" : "oliverdocument"},
                        { "type" : "Document", "id" : "georgedocument"},
                        { "type" : "Document", "id" : "dummy"}
                    ]
                },
            ]
        );

        let expected_entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "personaldoc":{"__entity":{"type":"Document","id":"oliverdocument"}},
                    },
                    "parents" : [
                        { "type" : "Document", "id" : "dummy"},
                        { "type" : "Document", "id" : "oliverdocument"}
                    ]
                }
            ]
        );

        expect_entity_slice_to(
            entities_json,
            expected_entities_json,
            &schema,
            &entity_manifest,
        );
    }

    #[test]
    fn test_entity_manifest_set_of_ancestors() {
        let mut pset = PolicySet::new();
        let policy = parse_policy(
            None,
            "permit(principal, action, resource)
when {
    principal in principal.managers
};",
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User in [User] = {
  name: String,
  managers: Set<User>
};

entity Document;

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
    ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");

        let entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "name" : "Oliver",
                        "managers": [
                            { "type" : "User", "id" : "george"},
                            { "type" : "User", "id" : "yihong"},
                            { "type" : "User", "id" : "ignored"},
                        ]
                    },
                    "parents" : [
                        { "type" : "User", "id" : "dummy"},
                        { "type" : "User", "id" : "george"},
                        { "type" : "User", "id" : "yihong"},
                    ]
                },
            ]
        );

        let expected_entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                        "managers": [
                            { "__entity": { "type" : "User", "id" : "george"}},
                            { "__entity": { "type" : "User", "id" : "yihong"}},
                            { "__entity": { "type" : "User", "id" : "ignored"}},
                        ]
                    },
                    "parents" : [
                        { "type" : "User", "id" : "george"},
                        { "type" : "User", "id" : "yihong"},
                    ]
                },
            ]
        );

        expect_entity_slice_to(
            entities_json,
            expected_entities_json,
            &schema,
            &entity_manifest,
        );
    }

    #[test]
    fn test_entity_manifest_multiple_branches() {
        let mut pset = PolicySet::new();
        let policy1 = parse_policy(
            None,
            r#"
permit(
  principal,
  action == Action::"Read",
  resource
)
when
{
  resource.readers.contains(principal)
};"#,
        )
        .unwrap();
        let policy2 = parse_policy(
            Some(PolicyID::from_string("Policy2")),
            r#"permit(
  principal,
  action == Action::"Read",
  resource
)
when
{
  resource.metadata.owner == principal
};"#,
        )
        .unwrap();
        pset.add(policy1.into()).expect("should succeed");
        pset.add(policy2.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User;

entity Metadata = {
   owner: User,
   time: String,
};

entity Document = {
  metadata: Metadata,
  readers: Set<User>,
};

action Read appliesTo {
  principal: [User],
  resource: [Document]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");

        let entities_json = serde_json::json!(
            [
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                    },
                    "parents" : [
                    ]
                },
                {
                    "uid": { "type": "Document", "id": "dummy"},
                    "attrs": {
                        "metadata": { "type": "Metadata", "id": "olivermetadata"},
                        "readers": [{"type": "User", "id": "oliver"}]
                    },
                    "parents": [],
                },
                {
                    "uid": { "type": "Metadata", "id": "olivermetadata"},
                    "attrs": {
                        "owner": { "type": "User", "id": "oliver"},
                        "time": "now"
                    },
                    "parents": [],
                },
            ]
        );

        let expected_entities_json = serde_json::json!(
            [
                {
                    "uid": { "type": "Document", "id": "dummy"},
                    "attrs": {
                        "metadata": {"__entity": { "type": "Metadata", "id": "olivermetadata"}},
                        "readers": [{ "__entity": {"type": "User", "id": "oliver"}}]
                    },
                    "parents": [],
                },
                {
                    "uid": { "type": "Metadata", "id": "olivermetadata"},
                    "attrs": {
                        "owner": {"__entity": { "type": "User", "id": "oliver"}},
                    },
                    "parents": [],
                },
                {
                    "uid" : { "type" : "User", "id" : "oliver"},
                    "attrs" : {
                    },
                    "parents" : [
                    ]
                },
            ]
        );

        expect_entity_slice_to(
            entities_json,
            expected_entities_json,
            &schema,
            &entity_manifest,
        );
    }

    #[test]
    fn test_entity_manifest_struct_equality() {
        let mut pset = PolicySet::new();
        // we need to load all of the metadata, not just nickname
        // no need to load actual name
        let policy = parse_policy(
            None,
            r#"permit(principal, action, resource)
when {
    principal.metadata.nickname == "timmy" && principal.metadata == {
        "friends": [ "oliver" ],
        "nickname": "timmy"
    }
};"#,
        )
        .expect("should succeed");
        pset.add(policy.into()).expect("should succeed");

        let schema = ValidatorSchema::from_cedarschema_str(
            "
entity User = {
  name: String,
  metadata: {
    friends: Set<String>,
    nickname: String,
  },
};

entity Document;

action BeSad appliesTo {
  principal: [User],
  resource: [Document]
};
        ",
            Extensions::all_available(),
        )
        .unwrap()
        .0;

        let entity_manifest = compute_entity_manifest(&schema, &pset).expect("Should succeed");
        assert_eq!(entity_manifest, entity_manifest);
    }
}