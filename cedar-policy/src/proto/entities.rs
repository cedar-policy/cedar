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

#![allow(clippy::use_self, reason = "readability")]

use super::ast::ProtobufConversionError;
use super::models;
use cedar_policy_core::{ast, entities, extensions};

impl TryFrom<models::Entities> for entities::Entities {
    type Error = ProtobufConversionError;

    fn try_from(v: models::Entities) -> Result<Self, Self::Error> {
        let entities: Vec<ast::Entity> = v
            .entities
            .into_iter()
            .map(ast::Entity::try_from)
            .collect::<Result<_, _>>()?;

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
        .and_then(|v| v.try_validate())
        .map_err(|e| ProtobufConversionError::InvalidValue(format!("invalid entities: {e}")))
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
            entities::Entities::try_from(models::Entities::from(&entities1)).unwrap()
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
            entities::Entities::try_from(models::Entities::from(&entities2)).unwrap()
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
            entities::Entities::try_from(models::Entities::from(&entities3)).unwrap()
        );
    }
}
