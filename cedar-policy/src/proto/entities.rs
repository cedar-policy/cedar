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

#![allow(clippy::use_self)]

use super::models;
use cedar_policy_core::{ast, entities, extensions};

impl From<&models::Entities> for entities::Entities {
    // PANIC SAFETY: experimental feature
    #[allow(clippy::expect_used)]
    fn from(v: &models::Entities) -> Self {
        let entities: Vec<ast::Entity> = v.entities.iter().map(ast::Entity::from).collect();

        // REVIEW (before stabilization): does `AssumeAlreadyComputed` make
        // sense here? It will be the case for protobufs produced from our
        // own serialization code, but others could produce protobufs in other
        // ways that may not be TC
        entities::Entities::from_entities(
            entities,
            None::<&entities::NoEntitiesSchema>,
            entities::TCComputation::AssumeAlreadyComputed,
            extensions::Extensions::all_available(),
        )
        .expect("protobuf entities should be valid")
    }
}

impl From<&entities::Entities> for models::Entities {
    fn from(v: &entities::Entities) -> Self {
        assert!(
            !v.is_partial(),
            "protobuf does not support encoding partial Entities"
        );
        Self {
            entities: v.iter().map(models::Entity::from).collect(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use cedar_policy_core::assert_deep_eq;
    use smol_str::SmolStr;
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::sync::Arc;

    #[test]
    fn entities_roundtrip() {
        // Empty Test
        let entities1 = entities::Entities::new();
        assert_deep_eq!(
            entities1,
            entities::Entities::from(&models::Entities::from(&entities1))
        );

        // Single Element Test
        let attrs = (1..=7)
            .map(|id| (format!("{id}").into(), ast::RestrictedExpr::val(true)))
            .collect::<HashMap<SmolStr, _>>();
        let entity = Arc::new(
            ast::Entity::new(
                r#"Foo::"bar""#.parse().unwrap(),
                attrs.clone(),
                HashSet::new(),
                HashSet::new(),
                BTreeMap::new(),
                extensions::Extensions::none(),
            )
            .unwrap(),
        );
        let mut entities2 = entities::Entities::new();
        entities2 = entities2
            .add_entities(
                [entity.clone()],
                None::<&entities::NoEntitiesSchema>,
                entities::TCComputation::AssumeAlreadyComputed,
                extensions::Extensions::none(),
            )
            .unwrap();
        assert_deep_eq!(
            entities2,
            entities::Entities::from(&models::Entities::from(&entities2))
        );

        // Two Element Test
        let entity2 = Arc::new(
            ast::Entity::new(
                r#"Bar::"foo""#.parse().unwrap(),
                attrs,
                HashSet::new(),
                HashSet::new(),
                BTreeMap::new(),
                extensions::Extensions::none(),
            )
            .unwrap(),
        );
        let mut entities3 = entities::Entities::new();
        entities3 = entities3
            .add_entities(
                [entity, entity2],
                None::<&entities::NoEntitiesSchema>,
                entities::TCComputation::AssumeAlreadyComputed,
                extensions::Extensions::none(),
            )
            .unwrap();
        assert_deep_eq!(
            entities3,
            entities::Entities::from(&models::Entities::from(&entities3))
        );
    }
}
