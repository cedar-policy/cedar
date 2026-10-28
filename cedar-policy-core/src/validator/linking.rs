/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Linking of partial schemas ([RFC 116](https://github.com/cedar-policy/rfcs/pull/116)).
//!
//! Linking resolves a name declared `external` in one schema against a
//! definition of the same name in another. A declaration left without a
//! definition stays `external`, so the result may itself be partial.
//!
//! This mirrors `Cedar/Validation/Linker.lean`: a collision check across
//! action types and entity types, a pairwise merge of the entity and action
//! maps, then a transitive closure of entity ancestors that may not enlarge
//! the ancestors of any defined entity type.
//!
//! Constructing the result closes it, so linking does not close it a second
//! time. It counts each definition's parents on either side of that closure
//! instead, which is what tells it whether closing enlarged one.
//!
//! The Lean model stores ancestors; a [`ValidatorSchema`] stores descendants.
//! Each input is inverted on the way in and the result is inverted on the way
//! out.

use crate::ast::{EntityType, EntityUID};
use crate::extensions::Extensions;
use crate::validator::{
    IncompleteSchemaError, SchemaError, ValidatorActionId, ValidatorEntityType,
    ValidatorEntityTypeKind, ValidatorSchema,
};
use miette::Diagnostic;
use std::collections::{HashMap, HashSet};
use thiserror::Error;

/// Errors reported by [`Linker::link`], and by the callers that require a
/// linked schema to be complete.
///
/// Separate from [`SchemaError`](crate::validator::SchemaError) on purpose.
/// Constructing a partial schema succeeds, so incompleteness is not a
/// construction failure, and linking has failure modes that no schema
/// constructor can produce.
#[derive(Debug, Diagnostic, Error)]
#[non_exhaustive]
pub enum LinkError {
    /// The schema still declares some entity types or actions `external`
    /// (RFC 116) rather than defining them.
    #[error(transparent)]
    #[diagnostic(transparent)]
    IncompleteSchema(#[from] IncompleteSchemaError),
    /// An entity type has the same name as the type of an action.
    #[error("entity type `{0}` is also the type of an action")]
    ActionEntityTypeDeclared(EntityType),
    /// Both schemas define the entity type.
    #[error("entity type `{0}` is defined twice")]
    DuplicateEntityType(EntityType),
    /// Both schemas define the action.
    #[error("action `{0}` is defined twice")]
    DuplicateAction(EntityUID),
    /// An external entity type links to an enumerated entity type.
    #[error("external entity type `{0}` links to an enumerated entity type")]
    ExternalIsEnum(EntityType),
    /// Linking would add ancestors to a defined entity type.
    #[error("linking would add ancestors to defined entity type `{0}`")]
    DefinedEntityAncestorsChanged(EntityType),
    /// Two declarations of an action have different parents.
    #[error("declarations of action `{0}` have different parents")]
    ExternalActionParentsMismatch(EntityUID),
    /// Linking would introduce an entity type that shadows a primitive or
    /// extension type.
    #[error("linking would make `{0}` shadow a built-in type")]
    #[diagnostic(help("linking does not support introducing a declaration that shadows a primitive or extension type"))]
    ShadowsBuiltinType(EntityType),
    /// The linked schema is not well formed. Reports the same error that
    /// constructing the merged declarations would.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Schema(#[from] SchemaError),
}

/// Links a set of schemas into one.
#[derive(Debug)]
pub struct Linker<'a> {
    /// The schemas to link.
    schemas: Vec<ValidatorSchema>,
    /// The active extensions, which decide whether a declaration shadows an
    /// extension type.
    extensions: &'a Extensions<'a>,
}

impl<'a> Linker<'a> {
    /// Construct a [`Linker`] over `schemas`.
    pub fn new(
        schemas: impl IntoIterator<Item = ValidatorSchema>,
        extensions: &'a Extensions<'a>,
    ) -> Self {
        Self {
            schemas: schemas.into_iter().collect(),
            extensions,
        }
    }

    /// Link the schemas into one.
    ///
    /// Linking is commutative and associative, so the result does not depend
    /// on the order or the grouping of the input. An empty input links to the
    /// empty schema.
    ///
    /// # Errors
    ///
    /// Returns a [`LinkError`] if the schemas do not link.
    pub fn link(self) -> Result<ValidatorSchema, LinkError> {
        let mut schemas = self.schemas;
        if schemas.is_empty() {
            // No schemas link to the empty schema.
            return Ok(ValidatorSchema::empty());
        }
        if schemas.len() == 1 {
            // One schema links to itself. It is already closed and already
            // well formed, and it declares whatever the result declares.
            #[expect(
                clippy::expect_used,
                reason = "the length is 1, so there is an element to pop"
            )]
            return Ok(schemas.pop().expect("one schema"));
        }

        // One pass over the inputs before merging. This answers every question
        // the checks below ask, so none of them has to scan the accumulator as
        // it grows.
        let inputs = schemas.len();
        let mut declared_by: HashMap<EntityType, usize> = HashMap::new();
        let mut action_types: HashSet<&EntityType> = HashSet::new();
        let mut total_actions = 0_usize;
        for schema in &schemas {
            for ety in schema.entity_type_names() {
                *declared_by.entry(ety.clone()).or_default() += 1;
            }
            for action in schema.action_ids() {
                action_types.insert(action.name().entity_type());
                total_actions += 1;
            }
        }

        // An action's entity type may not also be declared as an entity type.
        // The first failure in name order is reported, so a schema with more
        // than one reports the same one every time.
        if let Some(ety) = action_types
            .iter()
            .filter(|ety| declared_by.contains_key(**ety))
            .min()
        {
            return Err(LinkError::ActionEntityTypeDeclared((*ety).clone()));
        }

        let mut linked = Parts::with_capacity(declared_by.len(), total_actions);
        for schema in schemas {
            linked.link_in(Parts::from_schema(schema))?;
        }
        // Counting once at the end is enough: ancestors only grow as inputs
        // are added, so a definition that closing would enlarge at any step is
        // one the final closure enlarges too.
        let defined_parents = count_defined_parents(&linked.ets, &linked.et_ancestors);
        let linked = linked.into_schema();
        // Linking may not introduce a declaration that shadows a built-in
        // type. One that every input already declares is not introduced.
        let builtins = builtin_names(self.extensions);
        if let Some(ety) = linked
            .entity_type_names()
            .filter(|ety| {
                shadows_builtin(ety, &builtins) && declared_by.get(*ety).copied() != Some(inputs)
            })
            .min()
        {
            return Err(LinkError::ShadowsBuiltinType(ety.clone()));
        }
        // The linked schema must be one that constructing the merged
        // declarations would also produce, so it is held to the same checks.
        // Validating also closes it, which is the closure the next check reads.
        let linked = linked.try_validate()?;
        check_ancestors_unchanged(&defined_parents, &linked)?;
        Ok(linked)
    }
}

/// One schema, with the ancestor relation recovered from the stored
/// descendants. Mirrors Lean's `PartialSchema`, whose entries carry ancestors.
struct Parts {
    /// Entity types, keyed by name.
    ets: HashMap<EntityType, ValidatorEntityType>,
    /// Closed ancestors of each key of `ets`.
    et_ancestors: HashMap<EntityType, HashSet<EntityType>>,
    /// Actions, keyed by uid.
    acts: HashMap<EntityUID, ValidatorActionId>,
    /// Closed ancestors of each key of `acts`.
    act_ancestors: HashMap<EntityUID, HashSet<EntityUID>>,
}

impl Parts {
    /// The identity of linking, sized for the merge it will accumulate.
    fn with_capacity(entity_types: usize, actions: usize) -> Self {
        Self {
            ets: HashMap::with_capacity(entity_types),
            et_ancestors: HashMap::with_capacity(entity_types),
            acts: HashMap::with_capacity(actions),
            act_ancestors: HashMap::with_capacity(actions),
        }
    }

    /// Take one schema apart. The entries are moved out, so nothing here is
    /// cloned but the names that index the ancestor relation.
    fn from_schema(schema: ValidatorSchema) -> Self {
        let (ets, acts) = schema.into_parts();
        let mut et_ancestors: HashMap<EntityType, HashSet<EntityType>> = ets
            .keys()
            .map(|ety| (ety.clone(), HashSet::new()))
            .collect();
        for (parent, entry) in &ets {
            for child in &entry.descendants {
                if let Some(ancestors) = et_ancestors.get_mut(child) {
                    ancestors.insert(parent.clone());
                }
            }
        }
        let mut act_ancestors: HashMap<EntityUID, HashSet<EntityUID>> = acts
            .keys()
            .map(|uid| (uid.clone(), HashSet::new()))
            .collect();
        for (parent, entry) in &acts {
            for child in entry.descendants() {
                if let Some(ancestors) = act_ancestors.get_mut(child) {
                    ancestors.insert(parent.clone());
                }
            }
        }
        Self {
            ets,
            et_ancestors,
            acts,
            act_ancestors,
        }
    }

    /// Rebuild a [`ValidatorSchema`], inverting the ancestor relation back
    /// into the descendants each entry stores.
    fn into_schema(self) -> ValidatorSchema {
        let Self {
            ets,
            et_ancestors,
            acts,
            act_ancestors,
        } = self;
        // A parent absent from `ets` is skipped: it is referenced but not
        // declared, which `try_validate` reports.
        let mut et_descendants: HashMap<EntityType, HashSet<EntityType>> =
            HashMap::with_capacity(ets.len());
        for (child, ancestors) in &et_ancestors {
            for parent in ancestors {
                if ets.contains_key(parent) {
                    et_descendants
                        .entry(parent.clone())
                        .or_default()
                        .insert(child.clone());
                }
            }
        }
        let mut act_descendants: HashMap<EntityUID, HashSet<EntityUID>> =
            HashMap::with_capacity(acts.len());
        for (child, ancestors) in &act_ancestors {
            for parent in ancestors {
                if acts.contains_key(parent) {
                    act_descendants
                        .entry(parent.clone())
                        .or_default()
                        .insert(child.clone());
                }
            }
        }
        // The entries are owned here, so they are moved rather than cloned.
        let entity_types: Vec<_> = ets
            .into_values()
            .map(|mut ety| {
                ety.descendants = et_descendants.remove(ety.name()).unwrap_or_default();
                ety
            })
            .collect();
        let actions: Vec<_> = acts
            .into_values()
            .map(|mut action| {
                action.descendants = act_descendants.remove(action.name()).unwrap_or_default();
                action
            })
            .collect();
        ValidatorSchema::new(entity_types, actions)
    }

    /// Merge `c` into this schema, as Lean's `link` does apart from the
    /// closure and the action-entity-type check, which [`Linker::link`] runs
    /// once each.
    ///
    /// Entries this schema already holds and `c` does not are left in place.
    fn link_in(&mut self, mut c: Self) -> Result<(), LinkError> {
        for (ety, c_entry) in in_key_order(c.ets) {
            let c_ancestors = c.et_ancestors.remove(&ety).unwrap_or_default();
            // Take what is already here, so both sides can be moved into the
            // merge rather than cloned.
            let (entry, ancestors) = match self.ets.remove(&ety) {
                None => (c_entry, c_ancestors),
                Some(entry) => {
                    let ancestors = self.et_ancestors.remove(&ety).unwrap_or_default();
                    link_entity_type(&ety, (entry, ancestors), (c_entry, c_ancestors))?
                }
            };
            self.et_ancestors.insert(ety.clone(), ancestors);
            self.ets.insert(ety, entry);
        }
        for (uid, c_entry) in in_key_order(c.acts) {
            let c_ancestors = c.act_ancestors.remove(&uid).unwrap_or_default();
            let entry = match self.acts.remove(&uid) {
                None => c_entry,
                Some(entry) => {
                    let ancestors = self.act_ancestors.remove(&uid).unwrap_or_default();
                    link_action(&uid, (entry, ancestors), (c_entry, &c_ancestors))?
                }
            };
            self.act_ancestors.insert(uid.clone(), c_ancestors);
            self.acts.insert(uid, entry);
        }
        Ok(())
    }
}

/// The entries of `map` in key order, borrowed or owned as `map` is.
///
/// A loop that stops at its first failure reports whichever entry it reached
/// first, so it iterates in this order rather than in hash order.
fn in_key_order<K: Ord, V>(map: impl IntoIterator<Item = (K, V)>) -> Vec<(K, V)> {
    let mut entries: Vec<(K, V)> = map.into_iter().collect();
    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    entries
}

/// Link one action, as Lean's `PartialActionSchemaEntry.link` does. The kind
/// decides first, then the parents, which must agree whether or not either
/// side is a definition.
fn link_action(
    uid: &EntityUID,
    p: (ValidatorActionId, HashSet<EntityUID>),
    c: (ValidatorActionId, &HashSet<EntityUID>),
) -> Result<ValidatorActionId, LinkError> {
    let (p_entry, p_ancestors) = p;
    let (c_entry, c_ancestors) = c;
    let entry = match (p_entry.is_external(), c_entry.is_external()) {
        (false, false) => return Err(LinkError::DuplicateAction(uid.clone())),
        (true, true) | (true, false) => c_entry,
        (false, true) => p_entry,
    };
    if &p_ancestors != c_ancestors {
        return Err(LinkError::ExternalActionParentsMismatch(uid.clone()));
    }
    Ok(entry)
}

/// Is `entry` only declared `external`?
fn is_external_entity(entry: &ValidatorEntityType) -> bool {
    entry.is_external()
}

/// Link one entity type, as Lean's `PartialEntitySchemaEntry.link` does.
fn link_entity_type(
    ety: &EntityType,
    p: (ValidatorEntityType, HashSet<EntityType>),
    c: (ValidatorEntityType, HashSet<EntityType>),
) -> Result<(ValidatorEntityType, HashSet<EntityType>), LinkError> {
    let (p_entry, p_ancestors) = p;
    let (c_entry, c_ancestors) = c;
    match (is_external_entity(&p_entry), is_external_entity(&c_entry)) {
        (false, false) => Err(LinkError::DuplicateEntityType(ety.clone())),
        (true, true) => {
            let mut ancestors = p_ancestors;
            ancestors.extend(c_ancestors);
            Ok((p_entry, ancestors))
        }
        (true, false) => resolve_external_entity(ety, &p_ancestors, c_entry, c_ancestors),
        (false, true) => resolve_external_entity(ety, &c_ancestors, p_entry, p_ancestors),
    }
}

/// An external declaration with `parents` meets the definition `defined`,
/// whose own ancestors are `defined_ancestors`.
fn resolve_external_entity(
    ety: &EntityType,
    parents: &HashSet<EntityType>,
    defined: ValidatorEntityType,
    defined_ancestors: HashSet<EntityType>,
) -> Result<(ValidatorEntityType, HashSet<EntityType>), LinkError> {
    if matches!(defined.kind, ValidatorEntityTypeKind::Enum(_)) {
        return Err(LinkError::ExternalIsEnum(ety.clone()));
    }
    if parents.is_subset(&defined_ancestors) {
        Ok((defined, defined_ancestors))
    } else {
        Err(LinkError::DefinedEntityAncestorsChanged(ety.clone()))
    }
}

/// How many declared parents each defined entity type has.
///
/// [`Parts::into_schema`] keeps only the parents that are declared, so this
/// counts the same way; that is what makes the count comparable with one taken
/// from a schema.
fn count_defined_parents(
    ets: &HashMap<EntityType, ValidatorEntityType>,
    ancestors: &HashMap<EntityType, HashSet<EntityType>>,
) -> HashMap<EntityType, usize> {
    ets.iter()
        // An enumerated or external declaration imposes no constraint.
        .filter(|(_, entry)| matches!(entry.kind, ValidatorEntityTypeKind::Standard(_)))
        .map(|(ety, _)| {
            let parents = ancestors.get(ety).map_or(0, |parents| {
                parents.iter().filter(|p| ets.contains_key(*p)).count()
            });
            (ety.clone(), parents)
        })
        .collect()
}

/// Refuse if closing enlarged the ancestors of a defined entity type, as
/// Lean's `PartialEntitySchema.closeForLink` does.
///
/// `before` holds each definition's parent count from before `after` was
/// closed. Closing only ever adds ancestors, so a definition that has more of
/// them in `after` is one that closing enlarged.
fn check_ancestors_unchanged(
    before: &HashMap<EntityType, usize>,
    after: &ValidatorSchema,
) -> Result<(), LinkError> {
    let mut counts: HashMap<&EntityType, usize> = HashMap::with_capacity(before.len());
    for entry in after.entity_types() {
        for child in &entry.descendants {
            *counts.entry(child).or_default() += 1;
        }
    }
    if let Some(ety) = before
        .iter()
        .filter(|(ety, parents)| counts.get(*ety).copied().unwrap_or(0) > **parents)
        .map(|(ety, _)| ety)
        .min()
    {
        return Err(LinkError::DefinedEntityAncestorsChanged(ety.clone()));
    }
    Ok(())
}

/// The names a declaration may not shadow: the primitive types and the active
/// extension types. Built once per link rather than scanned per candidate.
fn builtin_names(extensions: &Extensions<'_>) -> HashSet<String> {
    ["Bool", "Long", "String"]
        .into_iter()
        .map(ToString::to_string)
        .chain(extensions.ext_types().map(ToString::to_string))
        .collect()
}

/// Does `name` shadow one of `builtins`?
fn shadows_builtin(name: &EntityType, builtins: &HashSet<String>) -> bool {
    // Only an unqualified name can shadow a built-in, and `Display` writes the
    // namespace, so a namespaced name cannot match.
    builtins.contains(&name.to_string())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::validator::types::{Attributes, OpenTag, Type};
    use cool_asserts::assert_matches;
    use std::str::FromStr;

    fn ety(name: &str) -> EntityType {
        name.parse().unwrap()
    }

    fn uid(name: &str) -> EntityUID {
        name.parse().unwrap()
    }

    fn set(names: &[&str]) -> HashSet<EntityType> {
        names.iter().map(|n| ety(n)).collect()
    }

    fn uid_set(names: &[&str]) -> HashSet<EntityUID> {
        names.iter().map(|n| uid(n)).collect()
    }

    /// An ancestor relation from `(name, ancestors)` pairs.
    fn relation(pairs: &[(&str, &[&str])]) -> HashMap<EntityType, HashSet<EntityType>> {
        pairs.iter().map(|(n, a)| (ety(n), set(a))).collect()
    }

    fn standard(name: &str) -> ValidatorEntityType {
        ValidatorEntityType::new_standard(
            ety(name),
            [],
            Attributes::with_attributes([]),
            OpenTag::ClosedAttributes,
            None,
            None,
        )
    }

    fn enumerated(name: &str) -> ValidatorEntityType {
        ValidatorEntityType::new_enum(
            ety(name),
            [],
            nonempty::nonempty![crate::ast::Eid::new("x")],
            None,
        )
    }

    fn external(name: &str) -> ValidatorEntityType {
        ValidatorEntityType::new_external(ety(name), [], None)
    }

    fn defined_action(name: &str) -> ValidatorActionId {
        ValidatorActionId::new_defined(uid(name), [], [], [], Type::any_record(), None)
    }

    fn external_action(name: &str) -> ValidatorActionId {
        ValidatorActionId::new_external(uid(name), [], None)
    }

    fn parts(
        ets: Vec<(ValidatorEntityType, &[&str])>,
        acts: Vec<(ValidatorActionId, &[&str])>,
    ) -> Parts {
        Parts {
            et_ancestors: ets
                .iter()
                .map(|(e, a)| (e.name().clone(), set(a)))
                .collect(),
            ets: ets
                .into_iter()
                .map(|(e, _)| (e.name().clone(), e))
                .collect(),
            act_ancestors: acts
                .iter()
                .map(|(a, anc)| (a.name().clone(), uid_set(anc)))
                .collect(),
            acts: acts
                .into_iter()
                .map(|(a, _)| (a.name().clone(), a))
                .collect(),
        }
    }

    // ----- count_defined_parents -----

    #[test]
    fn count_defined_parents_of_nothing() {
        assert!(count_defined_parents(&HashMap::new(), &HashMap::new()).is_empty());
    }

    #[test]
    fn count_defined_parents_counts_each_declared_parent() {
        let ets = HashMap::from([
            (ety("A"), standard("A")),
            (ety("B"), standard("B")),
            (ety("C"), standard("C")),
        ]);
        let ancestors = relation(&[("A", &["B", "C"]), ("B", &[]), ("C", &[])]);
        assert_eq!(
            count_defined_parents(&ets, &ancestors),
            HashMap::from([(ety("A"), 2), (ety("B"), 0), (ety("C"), 0)])
        );
    }

    #[test]
    fn count_defined_parents_skips_an_undeclared_parent() {
        // `into_schema` drops a parent it does not hold, so it is not counted.
        let ets = HashMap::from([(ety("A"), standard("A"))]);
        let ancestors = relation(&[("A", &["Z"])]);
        assert_eq!(
            count_defined_parents(&ets, &ancestors).get(&ety("A")),
            Some(&0)
        );
    }

    #[test]
    fn count_defined_parents_treats_a_missing_entry_as_no_parents() {
        let ets = HashMap::from([(ety("A"), standard("A"))]);
        assert_eq!(
            count_defined_parents(&ets, &HashMap::new()).get(&ety("A")),
            Some(&0)
        );
    }

    #[test]
    fn count_defined_parents_holds_only_definitions() {
        let ets = HashMap::from([
            (ety("A"), enumerated("A")),
            (ety("B"), external("B")),
            (ety("C"), standard("C")),
        ]);
        let ancestors = relation(&[("A", &["C"]), ("B", &["C"]), ("C", &[])]);
        let counts = count_defined_parents(&ets, &ancestors);
        assert_eq!(counts.into_keys().collect::<Vec<_>>(), vec![ety("C")]);
    }

    // ----- check_ancestors_unchanged -----

    /// Constructing a schema closes it, so this stands in for the schema that
    /// `try_validate` hands back.
    fn closed(src: &str) -> ValidatorSchema {
        // `A in [B]`, `B in [C]`: closing gives `A` two ancestors.
        ValidatorSchema::from_str(src).unwrap_or_else(|e| panic!("{src:?} should parse: {e}"))
    }

    const CHAIN: &str = "entity C;\nentity B in [C];\nentity A in [B];";

    #[test]
    fn check_ancestors_accepts_counts_that_match_the_closure() {
        let before = HashMap::from([(ety("A"), 2), (ety("B"), 1), (ety("C"), 0)]);
        assert_matches!(check_ancestors_unchanged(&before, &closed(CHAIN)), Ok(()));
    }

    #[test]
    fn check_ancestors_refuses_a_definition_the_closure_enlarged() {
        // `A` was declared with one parent and closing gave it two.
        let before = HashMap::from([(ety("A"), 1), (ety("B"), 1), (ety("C"), 0)]);
        assert_matches!(
            check_ancestors_unchanged(&before, &closed(CHAIN)),
            Err(LinkError::DefinedEntityAncestorsChanged(name)) => {
                assert_eq!(name, ety("A"));
            }
        );
    }

    #[test]
    fn check_ancestors_ignores_a_type_the_counts_omit() {
        // An enum or external declaration never reaches `before`, so the
        // closure is free to enlarge it.
        assert_matches!(
            check_ancestors_unchanged(&HashMap::new(), &closed(CHAIN)),
            Ok(())
        );
    }

    #[test]
    fn check_ancestors_accepts_a_closed_cycle() {
        // Both members arrive with each other and themselves as ancestors, so
        // closing adds nothing.
        let before = HashMap::from([(ety("A"), 2), (ety("B"), 2)]);
        assert_matches!(
            check_ancestors_unchanged(&before, &closed("entity A in [B];\nentity B in [A];")),
            Ok(())
        );
    }

    #[test]
    fn check_ancestors_reports_an_enlarged_definition_in_name_order() {
        let after = closed(CHAIN);
        for _ in 0..RUNS {
            // Closing enlarged both `A` and `B`.
            let before = HashMap::from([(ety("A"), 1), (ety("B"), 0), (ety("C"), 0)]);
            assert_matches!(
                check_ancestors_unchanged(&before, &after),
                Err(LinkError::DefinedEntityAncestorsChanged(name)) => {
                    assert_eq!(name, std::cmp::min(ety("A"), ety("B")));
                }
            );
        }
    }

    // ----- link_entity_type -----

    #[test]
    fn two_definitions_of_an_entity_type_are_refused() {
        assert_matches!(
            link_entity_type(
                &ety("A"),
                (standard("A"), set(&[])),
                (standard("A"), set(&[]))
            ),
            Err(LinkError::DuplicateEntityType(_))
        );
    }

    #[test]
    fn two_externals_union_their_parents() {
        assert_matches!(
            link_entity_type(
                &ety("A"),
                (external("A"), set(&["B"])),
                (external("A"), set(&["C"]))
            ),
            Ok((entry, ancestors)) => {
                assert!(entry.is_external());
                assert_eq!(ancestors, set(&["B", "C"]));
            }
        );
    }

    #[test]
    fn an_external_resolves_to_a_definition_that_covers_its_parents() {
        assert_matches!(
            link_entity_type(
                &ety("A"),
                (external("A"), set(&["B"])),
                (standard("A"), set(&["B", "C"]))
            ),
            Ok((entry, ancestors)) => {
                assert!(!entry.is_external());
                assert_eq!(ancestors, set(&["B", "C"]), "the definition's ancestors win");
            }
        );
    }

    #[test]
    fn an_external_parent_absent_from_the_definition_is_refused() {
        assert_matches!(
            link_entity_type(
                &ety("A"),
                (external("A"), set(&["Z"])),
                (standard("A"), set(&["B"]))
            ),
            Err(LinkError::DefinedEntityAncestorsChanged(_))
        );
    }

    #[test]
    fn an_external_may_not_resolve_to_an_enum() {
        assert_matches!(
            link_entity_type(
                &ety("A"),
                (external("A"), set(&[])),
                (enumerated("A"), set(&[]))
            ),
            Err(LinkError::ExternalIsEnum(_))
        );
    }

    #[test]
    fn an_enum_may_not_resolve_an_external_in_either_order() {
        assert_matches!(
            link_entity_type(
                &ety("A"),
                (enumerated("A"), set(&[])),
                (external("A"), set(&[]))
            ),
            Err(LinkError::ExternalIsEnum(_))
        );
    }

    // ----- link_action and link_in -----

    #[test]
    fn an_action_in_one_input_is_carried_over() {
        let mut p = parts(vec![], vec![(defined_action(r#"Action::"a""#), &[])]);
        let c = parts(vec![], vec![(defined_action(r#"Action::"b""#), &[])]);
        assert_matches!(p.link_in(c), Ok(()));
        assert_eq!(p.acts.len(), 2);
    }

    #[test]
    fn link_in_leaves_an_entry_the_other_side_lacks() {
        let mut p = parts(vec![(standard("A"), &[])], vec![]);
        let c = parts(vec![(standard("B"), &[])], vec![]);
        assert_matches!(p.link_in(c), Ok(()));
        assert_eq!(p.ets.len(), 2);
        assert!(p.ets.contains_key(&ety("A")) && p.ets.contains_key(&ety("B")));
    }

    #[test]
    fn two_external_actions_with_the_same_parents_link() {
        assert_matches!(
            link_action(
                &uid(r#"Action::"a""#),
                (external_action(r#"Action::"a""#), uid_set(&[r#"Action::"g""#])),
                (external_action(r#"Action::"a""#), &uid_set(&[r#"Action::"g""#])),
            ),
            Ok(entry) => assert!(entry.is_external())
        );
    }

    #[test]
    fn two_external_actions_with_different_parents_are_refused() {
        assert_matches!(
            link_action(
                &uid(r#"Action::"a""#),
                (
                    external_action(r#"Action::"a""#),
                    uid_set(&[r#"Action::"g""#])
                ),
                (external_action(r#"Action::"a""#), &uid_set(&[])),
            ),
            Err(LinkError::ExternalActionParentsMismatch(_))
        );
    }

    #[test]
    fn an_external_action_resolves_to_a_definition_with_the_same_parents() {
        assert_matches!(
            link_action(
                &uid(r#"Action::"a""#),
                (external_action(r#"Action::"a""#), uid_set(&[r#"Action::"g""#])),
                (defined_action(r#"Action::"a""#), &uid_set(&[r#"Action::"g""#])),
            ),
            Ok(entry) => assert!(!entry.is_external())
        );
    }

    #[test]
    fn a_definition_resolves_an_external_action_in_either_order() {
        assert_matches!(
            link_action(
                &uid(r#"Action::"a""#),
                (defined_action(r#"Action::"a""#), uid_set(&[])),
                (external_action(r#"Action::"a""#), &uid_set(&[])),
            ),
            Ok(entry) => assert!(!entry.is_external())
        );
    }

    #[test]
    fn an_external_action_whose_parents_differ_from_the_definition_is_refused() {
        assert_matches!(
            link_action(
                &uid(r#"Action::"a""#),
                (
                    external_action(r#"Action::"a""#),
                    uid_set(&[r#"Action::"g""#])
                ),
                (defined_action(r#"Action::"a""#), &uid_set(&[])),
            ),
            Err(LinkError::ExternalActionParentsMismatch(_))
        );
    }

    #[test]
    fn two_definitions_of_an_action_are_refused() {
        assert_matches!(
            link_action(
                &uid(r#"Action::"a""#),
                (defined_action(r#"Action::"a""#), uid_set(&[])),
                (defined_action(r#"Action::"a""#), &uid_set(&[])),
            ),
            Err(LinkError::DuplicateAction(_))
        );
    }

    /// Lean matches on the kind before comparing parents, so two definitions
    /// are a duplicate whatever their parents are.
    #[test]
    fn two_definitions_of_an_action_are_a_duplicate_even_with_different_parents() {
        assert_matches!(
            link_action(
                &uid(r#"Action::"a""#),
                (
                    defined_action(r#"Action::"a""#),
                    uid_set(&[r#"Action::"g""#])
                ),
                (defined_action(r#"Action::"a""#), &uid_set(&[])),
            ),
            Err(LinkError::DuplicateAction(_))
        );
    }

    // ----- builtin_names and shadows_builtin -----

    fn all_builtins() -> HashSet<String> {
        builtin_names(Extensions::all_available())
    }

    #[test]
    fn primitive_names_shadow_a_builtin() {
        let builtins = all_builtins();
        for name in ["Bool", "Long", "String"] {
            assert!(shadows_builtin(&ety(name), &builtins), "{name}");
        }
    }

    #[test]
    fn active_extension_names_shadow_a_builtin() {
        let builtins = all_builtins();
        for ext in Extensions::all_available().ext_types() {
            let name = EntityType::from_str(&ext.to_string()).unwrap();
            assert!(shadows_builtin(&name, &builtins), "{ext}");
        }
    }

    #[test]
    fn an_extension_name_is_ordinary_when_the_extension_is_inactive() {
        let decimal = ety("decimal");
        assert!(shadows_builtin(&decimal, &all_builtins()));
        assert!(!shadows_builtin(
            &decimal,
            &builtin_names(Extensions::none())
        ));
    }

    #[test]
    fn builtin_names_holds_the_primitives_whatever_the_extensions() {
        let none = builtin_names(Extensions::none());
        assert_eq!(none.len(), 3, "the three primitives: {none:?}");
        assert!(all_builtins().is_superset(&none));
    }

    #[test]
    fn a_namespaced_name_does_not_shadow_a_builtin() {
        assert!(!shadows_builtin(&ety("N::String"), &all_builtins()));
    }

    #[test]
    fn an_ordinary_name_does_not_shadow_a_builtin() {
        assert!(!shadows_builtin(&ety("User"), &all_builtins()));
    }

    // ----- Linker::link, end to end -----

    fn schema(src: &str) -> ValidatorSchema {
        ValidatorSchema::from_str(src).unwrap_or_else(|e| panic!("{src:?} should parse: {e}"))
    }

    #[track_caller]
    fn link_all(srcs: &[&str]) -> Result<ValidatorSchema, LinkError> {
        Linker::new(srcs.iter().map(|s| schema(s)), Extensions::all_available()).link()
    }

    #[track_caller]
    fn linked(srcs: &[&str]) -> ValidatorSchema {
        link_all(srcs).unwrap_or_else(|e| panic!("should link: {e}"))
    }

    fn type_names(s: &ValidatorSchema) -> Vec<String> {
        let mut v: Vec<String> = s.entity_type_names().map(ToString::to_string).collect();
        v.sort();
        v
    }

    fn ancestors_of(s: &ValidatorSchema, name: &str) -> Vec<String> {
        let mut v: Vec<String> = s
            .ancestors(&ety(name))
            .expect("declared")
            .map(ToString::to_string)
            .collect();
        v.sort();
        v
    }

    #[test]
    fn link_of_nothing_is_the_empty_schema() {
        assert_eq!(linked(&[]), ValidatorSchema::empty());
    }

    #[test]
    fn link_of_one_schema_returns_it_unchanged() {
        let one = schema("entity A;\nentity B in [A];");
        assert_eq!(linked(&["entity A;\nentity B in [A];"]), one);
    }

    #[test]
    fn linking_with_the_empty_schema_is_the_identity() {
        let src =
            "entity A;\nentity B in [A];\naction a appliesTo { principal: [B], resource: [B] };";
        assert_eq!(linked(&[src, ""]), schema(src));
    }

    #[test]
    fn two_disjoint_schemas_link_to_their_union() {
        let out = linked(&["entity A;", "entity B;"]);
        assert_eq!(type_names(&out), ["A", "B"]);
        assert!(out.is_complete());
    }

    /// Three schemas, each referring to the next one's definition through an
    /// attribute. Attribute references take no part in the ancestor closure.
    #[test]
    fn three_schemas_resolve_a_chain_of_externals() {
        let out = linked(&[
            "external entity B;\nentity A { b: B };",
            "external entity C;\nentity B { c: C };",
            "entity C;",
        ]);
        assert_eq!(type_names(&out), ["A", "B", "C"]);
        assert!(out.is_complete());
    }

    #[test]
    fn an_unresolved_external_remains_external() {
        let out = linked(&["external entity Z;\nentity A { z: Z };", "entity B;"]);
        assert!(!out.is_complete());
        assert_eq!(
            out.unresolved_declarations().count(),
            1,
            "`Z` is still only declared"
        );
    }

    #[test]
    fn linking_does_not_depend_on_the_order_of_the_input() {
        let a = "external entity B;\nentity A { b: B };";
        let b = "external entity C;\nentity B { c: C };";
        let c = "entity C;";
        let expected = linked(&[a, b, c]);
        for order in [[a, c, b], [b, a, c], [b, c, a], [c, a, b], [c, b, a]] {
            assert_eq!(linked(&order), expected, "order {order:?}");
        }
    }

    #[test]
    fn linking_does_not_depend_on_the_grouping_of_the_input() {
        let a = "external entity B;\nentity A { b: B };";
        let b = "external entity C;\nentity B { c: C };";
        let c = "entity C;";
        let all_at_once = linked(&[a, b, c]);
        let left = Linker::new([linked(&[a, b]), schema(c)], Extensions::all_available())
            .link()
            .expect("links");
        let right = Linker::new([schema(a), linked(&[b, c])], Extensions::all_available())
            .link()
            .expect("links");
        assert_eq!(left, all_at_once, "(a b) c");
        assert_eq!(right, all_at_once, "a (b c)");
    }

    #[test]
    fn a_duplicate_definition_among_three_inputs_is_refused() {
        assert_matches!(
            link_all(&["entity A;", "entity B;", "entity A;"]),
            Err(LinkError::DuplicateEntityType(_))
        );
    }

    #[test]
    fn a_duplicate_action_among_three_inputs_is_refused() {
        assert_matches!(
            link_all(&[
                "entity U;\naction a appliesTo { principal: [U], resource: [U] };",
                "entity V;",
                "entity W;\naction a appliesTo { principal: [W], resource: [W] };"
            ]),
            Err(LinkError::DuplicateAction(_))
        );
    }

    #[test]
    fn an_external_that_resolves_to_an_enum_is_refused() {
        assert_matches!(
            link_all(&[
                "external entity E;\nentity A { e: E };",
                "entity E enum [\"x\"];"
            ]),
            Err(LinkError::ExternalIsEnum(_))
        );
    }

    #[test]
    fn a_namespace_collision_introduced_by_a_link_is_refused() {
        // RFC 70 forbids `Foo` and `N::Foo` coexisting, so the merged
        // declarations denote no schema.
        assert_matches!(
            link_all(&[
                "entity Foo;",
                "entity Other;",
                "namespace N { entity Foo; }",
            ]),
            Err(LinkError::Schema(_))
        );
    }

    #[test]
    fn a_builtin_shadow_introduced_by_one_of_three_inputs_is_refused() {
        assert_matches!(
            link_all(&["entity A;", "entity B;", "entity String;"]),
            Err(LinkError::ShadowsBuiltinType(_))
        );
    }

    #[test]
    fn a_builtin_shadow_every_input_declares_is_accepted() {
        let out = linked(&[
            "entity String;\nentity A { s: String };",
            "external entity String;",
            "external entity String;",
        ]);
        assert!(type_names(&out).contains(&"String".to_string()));
    }

    // ----- stress -----

    /// Many small schemas. Each refers to the next one's definition through an
    /// attribute, so every external but the last resolves.
    #[test]
    fn stress_many_schemas() {
        const N: usize = 120;
        let mut srcs: Vec<String> = (0..N)
            .map(|i| {
                format!(
                    "external entity T{next};\nentity T{i} {{ next: T{next} }};\n\
                     action a{i} appliesTo {{ principal: [T{i}], resource: [T{i}] }};",
                    next = i + 1
                )
            })
            .collect();
        srcs.push(format!("entity T{N};"));
        let refs: Vec<&str> = srcs.iter().map(String::as_str).collect();
        let out = linked(&refs);
        assert_eq!(out.entity_type_names().count(), N + 1);
        assert_eq!(out.action_ids().count(), N);
        assert!(out.is_complete(), "every external but the last resolves");
    }

    /// A few large schemas. Each defines a block of entity types and declares
    /// the next block external, referring to it through an attribute.
    #[test]
    fn stress_a_few_big_schemas() {
        const BLOCKS: usize = 3;
        const PER_BLOCK: usize = 150;
        let srcs: Vec<String> = (0..BLOCKS)
            .map(|b| {
                let mut src = String::new();
                if b + 1 < BLOCKS {
                    for i in 0..PER_BLOCK {
                        src.push_str(&format!("external entity B{}_{i};\n", b + 1));
                    }
                }
                for i in 0..PER_BLOCK {
                    if b + 1 < BLOCKS {
                        src.push_str(&format!("entity B{b}_{i} {{ next: B{}_{i} }};\n", b + 1));
                    } else {
                        src.push_str(&format!("entity B{b}_{i};\n"));
                    }
                }
                src
            })
            .collect();
        let refs: Vec<&str> = srcs.iter().map(String::as_str).collect();
        let out = linked(&refs);
        assert_eq!(out.entity_type_names().count(), BLOCKS * PER_BLOCK);
        assert!(out.is_complete());
    }

    /// Complex parent relations. The defining schema spells out each type's
    /// full closed ancestor set, so closing the merge changes nothing, and the
    /// other input declares the same types external with a subset of parents.
    #[test]
    fn stress_complex_parent_relations() {
        const DEPTH: usize = 40;
        // L0 is the root; Lk declares every Lj with j < k as a parent, which is
        // already its closed ancestor set.
        let mut defining = String::from("entity L0;\n");
        for k in 1..DEPTH {
            let parents: Vec<String> = (0..k).map(|j| format!("L{j}")).collect();
            defining.push_str(&format!("entity L{k} in [{}];\n", parents.join(", ")));
        }
        // A cycle, closed within this schema, plus a wide fan out of the root.
        defining.push_str("entity C1 in [C2];\nentity C2 in [C1];\n");
        for w in 0..DEPTH {
            defining.push_str(&format!("entity W{w} in [L0];\n"));
        }
        // The other input declares the deepest type external with a subset of
        // its parents, which `resolve_external_entity` permits.
        // A partial schema must declare every name it refers to, so `L0` is
        // declared external here as well.
        let declaring = format!(
            "external entity L0;\nexternal entity L{last} in [L0];\n\
             entity Holder {{ deep: L{last} }};\n",
            last = DEPTH - 1
        );

        let out = linked(&[&defining, &declaring]);
        assert!(out.is_complete());
        assert_eq!(
            ancestors_of(&out, &format!("L{}", DEPTH - 1)).len(),
            DEPTH - 1,
            "the deepest type reaches every shallower one"
        );
        assert_eq!(ancestors_of(&out, "L0"), Vec::<String>::new());
        assert_eq!(ancestors_of(&out, "W0"), ["L0"]);
        // Both members of a cycle reach each other and themselves.
        assert_eq!(ancestors_of(&out, "C1"), ["C1", "C2"]);
        assert_eq!(ancestors_of(&out, "C2"), ["C1", "C2"]);
    }

    // ----- Parts round trip -----

    #[track_caller]
    fn assert_round_trips(src: &str) {
        let schema = ValidatorSchema::from_str(src).expect("parses");
        assert_eq!(
            Parts::from_schema(schema.clone()).into_schema(),
            schema,
            "round trip through Parts changed the schema: {src:?}"
        );
    }

    #[test]
    fn parts_round_trip_preserves_a_schema() {
        assert_round_trips(
            "entity A;\nentity B in [A];\naction a appliesTo { principal: [B], resource: [B] };",
        );
    }

    #[test]
    fn parts_round_trip_preserves_the_empty_schema() {
        assert_round_trips("");
    }

    #[test]
    fn parts_round_trip_preserves_a_closed_chain() {
        assert_round_trips("entity C;\nentity B in [C];\nentity A in [B];");
    }

    #[test]
    fn parts_round_trip_preserves_a_cycle() {
        assert_round_trips("entity A in [B];\nentity B in [A];");
    }

    #[test]
    fn parts_round_trip_preserves_externals_and_enums() {
        assert_round_trips(
            "external entity B;\nentity E enum [\"x\"];\nentity A in [B];\nexternal action g;",
        );
    }

    #[test]
    fn parts_round_trip_preserves_an_action_hierarchy() {
        assert_round_trips(
            "entity U;\naction g;\naction a in [g] appliesTo { principal: [U], resource: [U] };",
        );
    }

    // ----- deterministic error reporting -----

    /// Rust seeds each `HashMap` differently, so a handful of runs is enough
    /// to catch a report that follows hash order.
    const RUNS: usize = 20;

    #[test]
    fn in_key_order_sorts_by_key() {
        let map: HashMap<EntityType, u8> = [("C", 2), ("A", 0), ("B", 1)]
            .into_iter()
            .map(|(n, v)| (ety(n), v))
            .collect();
        let pairs: Vec<(&EntityType, &u8)> = in_key_order(&map);
        assert_eq!(
            pairs,
            vec![(&ety("A"), &0), (&ety("B"), &1), (&ety("C"), &2)]
        );
    }

    #[test]
    fn link_in_reports_a_duplicate_entity_type_in_name_order() {
        for _ in 0..RUNS {
            let mut p = parts(vec![(standard("A"), &[]), (standard("B"), &[])], vec![]);
            let c = parts(vec![(standard("A"), &[]), (standard("B"), &[])], vec![]);
            assert_matches!(
                p.link_in(c),
                Err(LinkError::DuplicateEntityType(name)) => assert_eq!(name, ety("A"))
            );
        }
    }

    #[test]
    fn link_in_reports_a_duplicate_action_in_name_order() {
        let a = r#"Action::"a""#;
        let b = r#"Action::"b""#;
        for _ in 0..RUNS {
            let mut p = parts(
                vec![],
                vec![(defined_action(a), &[]), (defined_action(b), &[])],
            );
            let c = parts(
                vec![],
                vec![(defined_action(a), &[]), (defined_action(b), &[])],
            );
            assert_matches!(
                p.link_in(c),
                Err(LinkError::DuplicateAction(name)) => assert_eq!(name, uid(a))
            );
        }
    }

    /// The schema parser refuses an entity type named `Action`, so this
    /// collision is only reachable through [`ValidatorSchema::new`].
    #[test]
    fn an_action_entity_type_collision_is_reported_in_name_order() {
        for _ in 0..RUNS {
            let a = ValidatorSchema::new([standard("Action"), standard("N::Action")], []);
            let b = ValidatorSchema::new(
                [standard("U")],
                [
                    defined_action(r#"Action::"a""#),
                    defined_action(r#"N::Action::"b""#),
                ],
            );
            assert_matches!(
                Linker::new([a, b], Extensions::all_available()).link(),
                Err(LinkError::ActionEntityTypeDeclared(name)) => {
                    assert_eq!(name, std::cmp::min(ety("Action"), ety("N::Action")));
                }
            );
        }
    }

    #[test]
    fn a_builtin_shadow_is_reported_in_name_order() {
        // Two names shadow a built-in, and neither is declared by every
        // input, so either would be a valid report.
        let expected = std::cmp::min(ety("String"), ety("decimal"));
        for _ in 0..RUNS {
            assert_matches!(
                link_all(&[
                    "entity A;",
                    "external entity String;\nexternal entity decimal;"
                ]),
                Err(LinkError::ShadowsBuiltinType(name)) => assert_eq!(name, expected)
            );
        }
    }
}
