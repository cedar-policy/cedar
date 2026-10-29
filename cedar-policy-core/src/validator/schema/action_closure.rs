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

//! Slicing a schema down to one action's transitive closure.
//!
//! The slice is a partial schema (RFC 116). It defines the action and every
//! action it is a member of, defines each enumerated entity type those actions
//! refer to, and declares `external` every other entity type they refer to.
//! On its own it gives the same action entities as the original schema for the
//! action and its ancestors, and it validates a request for the action as the
//! original schema does.

use std::collections::{BTreeSet, HashSet};

use crate::ast::{EntityType, EntityUID};
use crate::validator::types::{EntityKind, Type, TypeIterator};
use crate::validator::{
    ValidatorActionId, ValidatorEntityType, ValidatorEntityTypeKind, ValidatorSchema,
};

impl ValidatorSchema {
    /// The partial schema holding `action`'s transitive closure, or `None` if
    /// `action` is not declared in this schema.
    ///
    /// The result contains:
    ///
    /// - `action` and each of its ancestor actions, as declared here, with its
    ///   `appliesTo` and its context inline. Each keeps only the descendants
    ///   that are also in the closure, so the result holds exactly the
    ///   ancestor relation among those actions.
    /// - Each entity type that one of those actions applies to, or that one of
    ///   their context types mentions:
    ///   - an enumerated type is defined, with its values and no descendants,
    ///     so that a request naming a value it does not list is rejected as
    ///     the original schema rejects it;
    ///   - any other type is declared `external` with no parents. Request
    ///     validation accepts any entity id of such a type, as the original
    ///     schema does, and does not consult its ancestors.
    ///
    ///   Action entity types are not declared, since the actions that give
    ///   them are already in the result.
    ///
    /// The cost depends on the size of the closure, not of the schema.
    ///
    /// Linking the result with a schema that defines the same enumerated type
    /// fails, since both define it. A result that defines no enumerated type
    /// links with any schema that defines its external types.
    pub fn action_closure_for(&self, action: &EntityUID) -> Option<ValidatorSchema> {
        if !self.action_ids.contains_key(action) {
            return None;
        }
        // The cached action entity holds the closed ancestors, so the closure
        // is found without scanning every action.
        let ancestors: Vec<&EntityUID> = self
            .actions
            .get(action)
            .map(|entity| entity.ancestors().collect())
            .unwrap_or_default();
        let closure: HashSet<&EntityUID> = std::iter::once(action).chain(ancestors).collect();

        let actions: Vec<ValidatorActionId> = closure
            .iter()
            .filter_map(|uid| self.action_ids.get(*uid))
            .map(|entry| {
                let mut entry = entry.clone();
                // The closure is closed upward, so restricting a closed
                // descendant relation to it leaves the relation closed.
                entry.descendants.retain(|d| closure.contains(d));
                entry
            })
            .collect();

        let mut referenced: BTreeSet<EntityType> = BTreeSet::new();
        for entry in &actions {
            referenced.extend(entry.applies_to_principals().cloned());
            referenced.extend(entry.applies_to_resources().cloned());
            if let Some(context) = entry.context() {
                let leaves = TypeIterator {
                    stack: vec![context],
                };
                for leaf in leaves {
                    if let Type::Entity(EntityKind::Entity(lub)) = leaf {
                        referenced.extend(lub.iter().cloned());
                    }
                }
            }
        }
        // A referenced type that is not a declared entity type is an action
        // type (a valid schema references nothing undeclared), and the
        // actions that give it are already in the result.
        let entity_types = referenced.into_iter().filter_map(|ety| {
            let declared = self.entity_types.get(&ety)?;
            Some(match declared.kind {
                ValidatorEntityTypeKind::Enum(_) => {
                    // The descendants are dropped: they are not in the
                    // result, and an external type may not have an enumerated
                    // ancestor.
                    let mut entry = declared.clone();
                    entry.descendants.clear();
                    entry
                }
                _ => ValidatorEntityType::new_external(ety, [], None),
            })
        });

        Some(ValidatorSchema::new(entity_types, actions))
    }
}
